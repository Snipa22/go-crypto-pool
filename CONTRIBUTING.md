# Contributing

This project is part of the `go-tari-*`-adjacent ecosystem maintained by [Snipa22](https://github.com/Snipa22), providing Go tooling for the [Tari](https://github.com/tari-project/tari) network and mining-pool infrastructure.

## Workflow

- **Conventional Commits** — all commits must follow [Conventional Commits](https://www.conventionalcommits.org/) format (`feat:`, `fix:`, `docs:`, `chore:`, etc.). Versioning is automated from these via [release-please](https://github.com/googleapis/release-please) — commit type/scope directly determines the next SemVer bump, so get it right.
- **No direct pushes to `main`.** All changes land via pull request. (Exception: this initial scaffold commit, per repo-creation precedent.)
- **Rebase only — no merge commits, no squash-and-merge.** Keep your branch rebased on `main` before opening/updating a PR; a linear history is required and enforced by branch protection. If your PR shows a merge commit or unrelated history, rebase it (`git rebase main`) rather than merging.
- **1 approving review required** before merge. Repo maintainer can bypass for solo/trusted work; external contributions get the full review bar.
- **CI must be green** before merge (build, vet/lint, tests as configured — see `AGENTS.md` for exact commands).

## AI-assisted contributions

This project is developed with significant AI agent assistance (OpenCode, Claude, etc.) as a matter of course — that's normal here, not exceptional. Disclosure exists so reviewers know what to expect from a diff, not to gatekeep AI use.

- **Disclosure:** if a commit or PR was substantially generated or drafted by an AI agent, say so. Practically: add a line to the PR description (`Generated-with: <tool/model>` or equivalent free text) — no special tooling required, just don't hide it.
- **External contributors:** AI-assisted PRs are welcome under the same disclosure rule above. You're still responsible for the correctness of what you submit — "the AI wrote it" is not a defense for an untested or unreviewed change. PRs touching payout, financial, share-validation, or consensus-adjacent logic get held to a stricter review bar regardless of authorship.
- Repo-specific agent instructions live in `AGENTS.md` at repo root — read it before making agent-driven changes, and keep it updated if your workflow needs something it doesn't cover.

## Testing

New code needs test coverage. Every package added in this pass should have at least a placeholder test file wired up, even if trivial, so the CI test step has something real to run against as the codebase grows.

## License

See `LICENSE` at repo root — MIT.

## Private development phase

This repo is currently **private** and under active initial development. It will be open-sourced after extensive testing once the omni-pool backend and leaf stack are production-validated. Do not assume public visibility or external contribution norms apply yet — this section will be updated when the repo goes public.
