# What the tests cover

`go test ./...` is the check for this control plane. It rewrites the JSON records next to the API tests when those checks pass.

The tests show:

- Staff tokens verify as RS256 against a local key set. A staff token signed with the agent secret is rejected.
- Agent tokens are minted as HS256, require a non-empty server list, cannot carry migration scopes, and cannot mint further tokens.
- Console tickets last at most 120 seconds, are single-use, and are bound to the server and the minting subject. The WebSocket uses the ticket only.
- The default listen is `127.0.0.1:8080`. The process does not serve an OpenAPI UI.
- Rate limits are 60 mutate requests and 300 read requests per minute per token.
- The default executor does not dial Wings. GlassHosting-managed servers the caller does not own are not mutated.
- Server create claims one address pair and replays the same idempotency key.
- Panel import stays on `inventory_only` or `dry_run`. Confirm does not run. Rollback does not mutate.

Private network placement is outside this repository. Do not put host addresses, daemon tokens, or panel passwords in docs or evidence notes.
