# Panel import plan

Wings stays unwired on this path. `POST /v1/migrations/ptero` plans a move from a source Pterodactyl panel. It does not copy servers in this build.

## Environment

| Name | Role |
|------|------|
| `GLASSPANEL_MIGRATE_ENABLED` | `false` refuses `POST /v1/migrations/ptero`. Unset stays enabled |
| `GLASSPANEL_MIGRATE_MODE_MAX` | Ceiling is `inventory_only` or `dry_run` |
| `PTERO_SOURCE_API_URL` | Application API origin. Unset uses the in-process fixture and does not dial |
| `PTERO_SOURCE_API_TOKEN` | Read-scoped token. The value stays in the environment and is never logged |
| `PANEL_WINGS_EXECUTOR` | Default `noop`. This path does not dispatch Wings |

Do not put token values in git or in docs.

## What to expect

| Check | Result |
|-------|--------|
| `inventory_only` or `dry_run` | **202**. The plan lists only servers the caller may import. `servers_imported` is 0. Headers show the noop executor and Wings dispatch 0 |
| Refused servers | Absent from the live plan. A request that tries to include them is **403** and does not dial |
| Planned row | Carries a Glass server id and does not insert that id into `GET /v1/servers` |
| `import`, `import_and_cutover`, confirm | **403**. Rollback is a design stub (`design_only`, 72h, `applied: false`) and leaves status `planned` |
| Startup | Refuses a mode ceiling of `import` |

`POST /v1/migrations/{id}/remap` accepts internal Glass egg and node keys. Numeric Nest ids are **400**.

The same `Idempotency-Key` returns the same plan and does not read the source again.
