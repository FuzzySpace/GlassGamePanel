# Server create

`POST /v1/servers` with `name`, `egg_id`, and `entitlement_id` returns **202**. The in-process worker finishes the `server.create` job before that response is written. It claims the next free IPv4 and IPv6 pair from the configured allocation pool, stores a new Glass UUID, and leaves `wings_server_id` empty. The default executor does not dial Wings.

The same `Idempotency-Key` replays that response and does not claim a second pair. A new key for the same entitlement is **409**.

GlassHosting-managed servers the caller does not own are refused before a claim. The pool free count stays the same.

## Environment

| Name | Role |
|------|------|
| `PANEL_CREATE_NODE_ALLOWLIST` | Nodes `server.create` may target |
| `GLASSPANEL_CREATE_NODE_ID` | Optional alias. When set with the allowlist, it must be a member |
| `PANEL_ALLOC_POOL` | Allocation pool name. Any other name refuses to start |
| `GLASSPANEL_ALLOC_POOL` | Optional alias. Must match `PANEL_ALLOC_POOL` when both are set |
| `PANEL_WINGS_EXECUTOR` | Default `noop`. See [`phase-c-wings-allowlist.md`](phase-c-wings-allowlist.md) |

With the default executor, responses use `X-Glass-Executor: noop` and `X-Glass-Wings-Dispatch: 0`.

`go test ./...` covers create, the address pair, refuse-before-claim, the noop executor, and idempotency replay.
