// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync/atomic"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Session drives one miner connection's request/response loop on top of
// an already-accepted *leaflib.ManagedConnection. It never bypasses
// ManagedConnection's lifecycle guarantees: all reads go through mc.Read
// (which re-arms the rolling idle deadline — see connection.go), all
// writes go through mc.Write (which is already synchronized onto the
// connection's single writer goroutine), and teardown always ends in
// mc.Close so the ConnectionManager registry stays consistent.
type Session struct {
	mc     *leaflib.ManagedConnection
	server *Server

	sessionID string
	loggedIn  atomic.Bool
	address   atomic.Value // string
	worker    atomic.Value // string

	// shareCount/blockCount are local diagnostic counters only — solo
	// mode has no share table and no backend to forward to (see
	// cmd/leaf-solo's doc comment); a share only matters here as
	// hashrate-estimation signal.
	shareCount atomic.Uint64
	blockCount atomic.Uint64
}

func newSession(mc *leaflib.ManagedConnection, server *Server) *Session {
	id, _ := newJobID() // reuse the same random-hex helper; collisions are cosmetic only
	s := &Session{mc: mc, server: server, sessionID: id}
	s.address.Store("")
	s.worker.Store("")
	return s
}

// Run is the session's read loop. It returns when the connection closes
// for any reason (remote EOF, idle timeout, manager shutdown). The
// caller (Server.handleConn) owns calling mc.Close afterward.
func (s *Session) Run(ctx context.Context) {
	scanner := bufio.NewScanner(s.mc)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		s.handleLine(line)
	}
}

func (s *Session) handleLine(line string) {
	var req Request
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		s.writeResponse(0, nil, fmt.Sprintf("invalid request: %v", err))
		return
	}
	switch req.Method {
	case "login":
		s.handleLogin(req)
	case "getjob":
		s.handleGetJob(req)
	case "submit":
		s.handleSubmit(req)
	default:
		s.writeResponse(req.ID, nil, fmt.Sprintf("unknown method: %s", req.Method))
	}
}

func (s *Session) handleLogin(req Request) {
	var params LoginParams
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.writeResponse(req.ID, nil, fmt.Sprintf("invalid login params: %v", err))
			return
		}
	}
	if params.Address == "" {
		s.writeResponse(req.ID, nil, "login requires a non-empty address")
		return
	}
	s.address.Store(params.Address)
	s.worker.Store(params.Worker)
	s.loggedIn.Store(true)

	job := s.server.jobManager.Current()
	if job == nil {
		s.writeResponse(req.ID, nil, "no job template available yet, retry shortly")
		return
	}
	s.writeResponse(req.ID, LoginResult{
		Status:    "ok",
		SessionID: s.sessionID,
		Job:       jobPayload(job),
	}, "")
}

func (s *Session) handleGetJob(req Request) {
	if !s.loggedIn.Load() {
		s.writeResponse(req.ID, nil, "login required before getjob")
		return
	}
	job := s.server.jobManager.Current()
	if job == nil {
		s.writeResponse(req.ID, nil, "no job template available yet, retry shortly")
		return
	}
	s.writeResponse(req.ID, jobPayload(job), "")
}

func (s *Session) handleSubmit(req Request) {
	if !s.loggedIn.Load() {
		s.writeResponse(req.ID, nil, "login required before submit")
		return
	}
	var params SubmitParams
	if len(req.Params) == 0 {
		s.writeResponse(req.ID, nil, "submit requires params")
		return
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.writeResponse(req.ID, nil, fmt.Sprintf("invalid submit params: %v", err))
		return
	}

	job, ok := s.server.jobManager.GetJob(params.JobID)
	if !ok {
		s.writeResponse(req.ID, SubmitResult{Status: StatusRejected}, "unknown or stale job_id, request a new job")
		return
	}

	nonceBytes, err := hex.DecodeString(params.Nonce)
	if err != nil || len(nonceBytes) != 8 {
		s.writeResponse(req.ID, SubmitResult{Status: StatusRejected}, "nonce must be 8 bytes, hex-encoded little-endian uint64")
		return
	}
	nonce := leBytesToUint64(nonceBytes)

	share := &poolpb.Share{
		Algo:           poolpb.Algo_ALGO_SHA3X,
		Network:        s.server.network,
		BlockDiff:      safeInt64(job.StaticDifficulty),
		BlockHeight:    int64(job.Height),
		PaymentAddress: s.address.Load().(string),
		Identifier:     s.worker.Load().(string),
		RawProof: &poolpb.Share_Sha3XProof{
			Sha3XProof: &poolpb.SHA3XProof{
				Header: job.Header,
				Nonce:  nonce,
			},
		},
	}

	valid, err := s.server.validator.Validate(context.Background(), share)
	if err != nil && err != validator.ErrWrongProofType {
		s.writeResponse(req.ID, SubmitResult{Status: StatusRejected}, fmt.Sprintf("validation error: %v", err))
		return
	}
	if !valid {
		s.writeResponse(req.ID, SubmitResult{Status: StatusRejected}, "share does not meet configured difficulty or is cryptographically invalid")
		return
	}

	// Valid share (met the configured static share difficulty). This is
	// local diagnostic/hashrate-estimation signal only — solo mode has
	// no share table and no backend to forward it to.
	s.shareCount.Add(1)
	diff := validator.SHA3XHeaderDiff(nonce, job.Header)

	if job.NetworkTargetDifficulty == 0 || diff < job.NetworkTargetDifficulty {
		s.writeResponse(req.ID, SubmitResult{Status: StatusOK, Difficulty: diff}, "")
		return
	}

	// Meets full block difficulty: construct the real submission from
	// the already-fetched real GRPC template/coinbase data and submit
	// it for real. Mirrors go-tari-sha3x-solo-stratum's SubmitJob
	// (subsystems/poolStratum/miner.go, ~line 493).
	block := cloneBlockWithNonce(job.Result.GetBlock(), nonce)
	_, err = s.server.node.SubmitBlock(context.Background(), block)
	if err != nil {
		s.server.logger.Printf("solo: SubmitBlock failed for session %s (job %s, height %d): %v", s.sessionID, job.ID, job.Height, err)
		s.writeResponse(req.ID, SubmitResult{Status: StatusBlockRejected, Difficulty: diff}, err.Error())
		return
	}

	s.blockCount.Add(1)
	s.server.logger.Printf("solo: BLOCK FOUND by session %s (address %s) at height %d, job %s, diff %d", s.sessionID, s.address.Load(), job.Height, job.ID, diff)
	s.writeResponse(req.ID, SubmitResult{Status: StatusBlockFound, Difficulty: diff}, "")

	// A block was found; the current template is now stale for everyone.
	// Force an immediate refresh rather than waiting on the poll timers.
	go func() {
		if _, err := s.server.jobManager.Refresh(context.Background()); err != nil {
			s.server.logger.Printf("solo: post-block-find job refresh failed: %v", err)
		}
	}()
}

func (s *Session) writeResponse(id int, result any, errMsg string) {
	resp := Response{ID: id, Result: result, Error: errMsg}
	buf, err := json.Marshal(resp)
	if err != nil {
		s.server.logger.Printf("solo: failed to marshal response for session %s: %v", s.sessionID, err)
		return
	}
	buf = append(buf, '\n')
	if err := s.mc.Write(buf); err != nil {
		// Connection is going away; nothing more to do here, Run's
		// scanner loop will observe the resulting read error/EOF and
		// exit, and the caller closes mc.
		_ = err
	}
}

// pushJob sends an unsolicited "job" push for a newly-refreshed Job.
func (s *Session) pushJob(job *Job) {
	if !s.loggedIn.Load() {
		return
	}
	push := Push{Method: "job", Params: jobPayload(job)}
	buf, err := json.Marshal(push)
	if err != nil {
		return
	}
	buf = append(buf, '\n')
	_ = s.mc.Write(buf)
}

func jobPayload(job *Job) JobPayload {
	return JobPayload{
		JobID:      job.ID,
		Height:     job.Height,
		Header:     hex.EncodeToString(job.Header),
		Difficulty: job.StaticDifficulty,
		Algo:       "sha3x",
	}
}

func leBytesToUint64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v |= uint64(b[i]) << (8 * i)
	}
	return v
}

// safeInt64 converts a uint64 to int64 by clamping to math.MaxInt64
// rather than allowing a silent two's-complement wraparound. This
// matters here specifically because poolpb.Share.BlockDiff is int64 on
// the wire, while JobManagerConfig.StaticDifficulty (and any future
// vardiff-derived difficulty) is uint64 -- a naive int64(x) conversion
// of a uint64 value at or above 1<<63 wraps to a NEGATIVE int64, which
// would make validator.SHA3XValidator's `share.GetBlockDiff() > 0` guard
// evaluate false and SILENTLY SKIP the difficulty check entirely,
// accepting any cryptographically-valid-but-arbitrarily-easy share as
// if it met the configured difficulty. Found via a real failing test
// (TestSessionSubmitCryptographicallyInvalid used math.MaxUint64 as a
// deliberately-impossible-to-meet difficulty and got a false accept)
// during independent re-verification of this package -- clamping here
// is the fix, not a workaround in the test.
func safeInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// cloneBlockWithNonce returns a deep copy of block (via proto.Clone, to
// avoid copying protobuf's internal sync.Mutex-bearing MessageState by
// value) with Header.Nonce set to nonce, so the shared job template
// isn't mutated by a (potentially losing) submission race between
// miners on the same job.
func cloneBlockWithNonce(block *tari_generated.Block, nonce uint64) *tari_generated.Block {
	if block == nil {
		return nil
	}
	blockCopy := proto.Clone(block).(*tari_generated.Block)
	if blockCopy.Header == nil {
		blockCopy.Header = &tari_generated.BlockHeader{}
	}
	blockCopy.Header.Nonce = nonce
	return blockCopy
}
