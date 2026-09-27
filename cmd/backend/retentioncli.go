// Manual, ops-triggered "retention" subcommand for the backend binary:
//
//	backend retention run [-algo=ALGO] [-pool-type=TYPE] [-dsn=...] [-yes]
//
// This wraps the EXISTING real db.ListHeightPartitions/
// db.DropOldPartitions plumbing (the same whole-partition-drop
// mechanism internal/backend/retention's scheduled poll loop uses —
// see that package's doc comment for why this is a PARTITION-DROP
// design, never row-level DELETE) via buildRetentionConfig, so a
// manual run computes exactly the same cutoff height the scheduled
// job would have used on its next tick. This file adds no new write
// path to the schema; it is strictly a human-in-the-loop trigger for
// an operator who wants to run (or preview) a cleanup pass right now
// — e.g. right after lowering GCPOOL_RETENTION_BLOCKS, or to confirm
// what the next scheduled pass will drop before it runs.
//
// Without -algo/-pool-type, every configured target (from the same
// GCPOOL_RETENTION_* environment variables buildRetentionConfig
// already reads) is evaluated. With -algo and -pool-type, only that
// one target is evaluated (still using its configured retention
// window; there's no way to pass an ad-hoc window on this CLI —
// that keeps this command's decision identical to what the scheduled
// job would do, rather than becoming a second, divergent place drop
// decisions can be made from).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/backend/retention"
)

// retentionCLITimeout bounds every DB call the retention subcommand
// makes (connect + every target's list + drop calls) -- generous for
// a manual, one-off ops invocation against a real Postgres instance,
// but still bounded. Longer than blockCLITimeout since a full run can
// touch every (algo, pool_type) combination, not just one row.
const retentionCLITimeout = 2 * time.Minute

// runRetentionCommand dispatches `backend retention <subcommand> ...`.
// args is os.Args with both "backend" and "retention" already
// stripped off (i.e. args[0], if present, is the subcommand name:
// only "run" today).
func runRetentionCommand(args []string) error {
	if len(args) == 0 {
		return errors.New(`retention: missing subcommand, want "run"`)
	}
	switch args[0] {
	case "run":
		return runRetentionRun(args[1:])
	default:
		return fmt.Errorf(`retention: unrecognized subcommand %q, want "run"`, args[0])
	}
}

// runRetentionRun implements `retention run`: parse flags, connect to
// Postgres (using -dsn or GCPOOL_DB_DSN, matching run()'s own DSN
// resolution and blockcli.go's convention), build the same
// retention.Config the scheduled job would use from GCPOOL_RETENTION_*
// env vars, optionally narrow it to one -algo/-pool-type target, and
// -- only if -yes was passed -- actually call RunOnce. Without -yes,
// this prints every target's frontier/cutoff/would-drop partitions and
// returns an error (nonzero exit) without dropping anything.
func runRetentionRun(args []string) error {
	fs := flag.NewFlagSet("backend retention run", flag.ContinueOnError)
	algo := fs.String("algo", "", "restrict to one algo (must be paired with -pool-type). Default: every configured target.")
	poolType := fs.String("pool-type", "", "restrict to one pool_type (must be paired with -algo). Default: every configured target.")
	dsn := fs.String("dsn", os.Getenv("GCPOOL_DB_DSN"), "Postgres DSN. Defaults to GCPOOL_DB_DSN if unset.")
	yes := fs.Bool("yes", false, "actually drop aged-out partitions. Without this flag, every target's frontier/cutoff and the partitions that WOULD be dropped are printed and nothing is written.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: backend retention run [-algo=ALGO] [-pool-type=TYPE] [-dsn=...] [-yes]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if (*algo == "") != (*poolType == "") {
		fs.Usage()
		return errors.New("retention run: -algo and -pool-type must be set together, or both left empty")
	}
	if *algo != "" {
		if err := db.ValidateAlgo(*algo); err != nil {
			return fmt.Errorf("retention run: %w", err)
		}
		if err := db.ValidatePoolType(*poolType); err != nil {
			return fmt.Errorf("retention run: %w", err)
		}
	}
	if *dsn == "" {
		return errors.New("retention run: no DSN: pass -dsn or set GCPOOL_DB_DSN")
	}

	// This subcommand deliberately does not go through loadConfig()/
	// -config (see BRIEF_05_backend.md's scope carve-out for CLI
	// subcommands) -- it builds just the two fields
	// buildRetentionConfig actually needs directly from the same
	// GCPOOL_RETENTION_POLL_INTERVAL/GCPOOL_RETENTION_BLOCKS env vars
	// the scheduled job itself reads via loadConfig, preserving this
	// command's existing env-var-only behavior unchanged.
	retentionCfg, enabled, err := buildRetentionConfig(config{
		retentionPollInterval: envOrDuration("GCPOOL_RETENTION_POLL_INTERVAL", defaultRetentionPollInterval),
		retentionBlocks:       envOrInt64("GCPOOL_RETENTION_BLOCKS", 0),
	})
	if err != nil {
		return fmt.Errorf("retention run: %w", err)
	}
	if !enabled {
		return errors.New("retention run: no retention window configured (set GCPOOL_RETENTION_BLOCKS or GCPOOL_RETENTION_<ALGO>_<POOL_TYPE>_BLOCKS before running this command)")
	}
	if *algo != "" {
		var narrowed []retention.Target
		for _, t := range retentionCfg.Targets {
			if t.Algo == *algo && t.PoolType == *poolType {
				narrowed = append(narrowed, t)
			}
		}
		if len(narrowed) == 0 {
			return fmt.Errorf("retention run: no configured retention window for %s/%s", *algo, *poolType)
		}
		retentionCfg.Targets = narrowed
	}

	ctx, cancel := context.WithTimeout(context.Background(), retentionCLITimeout)
	defer cancel()

	pool, err := db.Open(ctx, db.Config{DSN: *dsn})
	if err != nil {
		return fmt.Errorf("retention run: connecting to database: %w", err)
	}
	defer pool.Close()
	repo := retentionRepositoryAdapter{pool: pool}

	if !*yes {
		log.Print("retention run: -yes not set, dry run only -- listing what each target would drop")
		var wouldDrop, errs int
		for _, t := range retentionCfg.Targets {
			partitions, err := repo.ListHeightPartitions(ctx, t.Algo, t.PoolType)
			if err != nil {
				log.Printf("retention run: %s/%s: listing partitions: %v", t.Algo, t.PoolType, err)
				errs++
				continue
			}
			if len(partitions) == 0 {
				log.Printf("retention run: %s/%s: no partitions exist yet, nothing to do", t.Algo, t.PoolType)
				continue
			}
			var frontier int64
			for _, p := range partitions {
				if p.RangeEnd > frontier {
					frontier = p.RangeEnd
				}
			}
			cutoff := frontier - t.RetentionBlocks
			var candidates []string
			for _, p := range partitions {
				if p.RangeEnd <= cutoff {
					candidates = append(candidates, p.Name)
				}
			}
			log.Printf("retention run: %s/%s: frontier=%d retention_blocks=%d cutoff=%d: %d/%d partition(s) exist, would drop %d: %v",
				t.Algo, t.PoolType, frontier, t.RetentionBlocks, cutoff, len(partitions), len(partitions), len(candidates), candidates)
			wouldDrop += len(candidates)
		}
		return fmt.Errorf("retention run: dry run only: would drop %d partition(s) across %d target(s), %d list error(s) (pass -yes to apply)", wouldDrop, len(retentionCfg.Targets), errs)
	}

	runner := retention.New(repo, retentionCfg)
	result := runner.RunOnce(ctx)
	for _, tr := range result.Targets {
		if tr.Err != nil {
			log.Printf("retention run: %s/%s: %v", tr.Algo, tr.PoolType, tr.Err)
			continue
		}
		log.Printf("retention run: %s/%s: dropped %d partition(s): %v", tr.Algo, tr.PoolType, len(tr.Dropped), tr.Dropped)
		for _, sp := range tr.Skipped {
			log.Printf("retention run: %s/%s: partition %s NOT dropped (block id=%d height=%d still unresolved, unlocked=false)",
				tr.Algo, tr.PoolType, sp.Name, sp.BlockID, sp.BlockHeight)
		}
	}
	log.Printf("retention run: done: %d target(s) checked, %d partition(s) dropped, %d partition(s) skipped (unresolved block), %d error(s)",
		result.TargetsChecked, result.PartitionsDropped, result.PartitionsSkipped, result.Errors)
	if result.Errors > 0 {
		return fmt.Errorf("retention run: completed with %d target error(s)", result.Errors)
	}
	return nil
}
