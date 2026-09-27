# Wings dial

This build accepts `PANEL_WINGS_EXECUTOR=real` and enforces `PANEL_WINGS_ALLOWLIST`. The default is `noop`. This page names environment variables only. Do not put token values here.

## Environment

| Name | Default | Behavior |
|------|---------|----------|
| `PANEL_WINGS_EXECUTOR` | `noop` | `noop` or `real`. Any other value refuses to start |
| `PANEL_WINGS_ALLOWLIST` | empty | Comma-separated Glass UUIDs. Empty means zero Wings dials, including when the executor is `real`. A node id does not authorize a dial |
| `PANEL_WINGS_BASE_URL` | empty | Wings daemon origin: scheme, host, and port. No path, query, fragment, or userinfo |
| `PANEL_WINGS_TOKEN` | empty | Wings daemon bearer token. Never logged and never placed on the URL |

`PANEL_WINGS_BASE_URL` and `PANEL_WINGS_TOKEN` must both be set or both be empty. Both empty is allowed when the executor is `real`. An allowlisted power or file list then returns **502** `wings_dial_failed` with dispatch 0.

`PANEL_CREATE_NODE_ALLOWLIST` does not authorize a Wings dial.

## What stays refused

GlassHosting-managed servers the caller does not own return **403** with Wings dispatch **0**, including when that UUID is also on `PANEL_WINGS_ALLOWLIST`. Those UUIDs are not passed to the Wings client.

The process refuses to boot when the embedded deny catalog does not match. It logs a checksum of that catalog. It does not log allowlist values or the daemon token.

## What dials

When the executor is `real`, the path UUID is on `PANEL_WINGS_ALLOWLIST`, the target is not refused, and the daemon origin and token are set:

- **Power** posts `{"action":"start"|"stop"|"restart"|"kill"}` to the daemon power route with `Authorization: Bearer`.
- **File list** gets the daemon list-directory route. The same allowlist and refuse rules apply.

`X-Glass-Wings-Dispatch` is `1` only after a completed HTTP round trip, including a Wings 4xx or 5xx. The client copies `X-Request-Id` onto the Wings request. Redirects are not followed. A transport failure is **502** `wings_dial_failed` and dispatch stays `0`.

Create, backups, migrations, and idempotency replays do not dial. File writes are in [`phase-d2-files-write.md`](phase-d2-files-write.md). Console tickets stay local and do not dial. `noop` never dials.
