# internal/backend/db

Placeholder for the backend's Postgres schema and migrations.

**Schema pending — see `OmniPool-Architecture.md` open items** (maintainer's private Obsidian vault). In particular:

- Share-table schema: query-volume-driven design (indexing/partitioning strategy) is not yet drafted.
- Per-algo PPLNS depth/retention design needs to be co-designed with the partitioning strategy.
- Four algo-partitioned share streams (RXT / C29 / SHA3X / RXM) — not one commingled table with a discriminator column — but exact column layout and partitioning shape are unresolved.

Do not add a real schema/migration here without an explicit maintainer decision on the above.
