# GlassGamePanel API

Draft contract: [`openapi/glass-game-panel-v1.openapi.yaml`](../openapi/glass-game-panel-v1.openapi.yaml) (`0.1.5-stub`).

Humans and agents share this API. A UI is another client. Wings is the current executor.

## What it covers

- Servers, power, console (ticket and WebSocket), files, backups, and metrics
- Portal OIDC for staff, and agent tokens that cannot mint further tokens
- A Pterodactyl import plan that defaults to inventory only
- Glass Watch stays a separate product
- One email is one account across Portal, GlassGamePanel, and Watch

## Refuse

The API refuses GlassHosting-managed servers the caller does not own. Those requests do not dial Wings and do not claim an allocation. The machine catalog lives in the OpenAPI extension and in the embedded deny file the tests compare. It is not restated here.

Rate limits are 60 mutate requests and 300 read requests per minute per token.

## Free Wings

Operator-owned Wings nodes use [`packaging/free`](../packaging/free/README.md). That installer is DIY. It is not GlassHosting capacity and it is not WHMCS.

Questions: GitHub Discussions category `free-ggp`, or sales@glasshosting.com.
