# GlassGamePanel free · Wings one-click

Glasshouse Holding Group / GlassHosting / GlassGamePanel

Branded installer for an **operator-owned** Wings node. Free means DIY: you install Wings on a machine you control and connect it to a panel you control.

This package does not include GlassHosting game-server capacity. It is not WHMCS.

Package: `glassgamepanel-wings-free-v0.1.0` (files here use the prefix `glassgamepanel-wings-free-`).

## Before you run it

Verify the checksums in this directory, then run the script from the unpacked folder:

```bash
cd packaging/free
sha256sum -c SHA256SUMS
```

Download the tree, check `SHA256SUMS`, then run `install.sh`. Do not pipe an unverified script from the internet into a shell. `SHA256SUMS` covers the files in this package.

Paste your panel configuration into the installer, not this README. The feedback address below is for people. It is not a panel URL.

## Your panel only

Use the URL and node token from **your** panel. Examples use `YOUR_PANEL_URL` and `YOUR_NODE_TOKEN`. This package contains no GlassHosting production token, JWT secret, Wings node token, or panel database credential.

The installer refuses GlassHosting production panel addresses, including hosts on `glasshosting.com`, and it refuses configuration that names GlassHosting-managed servers you do not own. On a match it prints `INSTALLER_REFUSE`, exits with an error, and does **not** install Wings, enroll a node, or write a config. Servers you do not own also print `REFUSED: GlassHosting-managed servers you do not own`. A refused panel address also prints `ENROLL REMOTE REFUSE`.

If the panel URL is missing or still a placeholder, enrollment stops. The installer will not fill in a GlassHosting URL. There is no demo panel in this package.

## What this install does

Primary OS: Ubuntu **22.04** and **24.04** LTS, **x86_64**.  
Optional OS: Debian **12** x86_64. All three use the distro package `docker.io`. The package name does not change between them.

Wings is the upstream Pterodactyl Wings daemon (pinned in `upstream/WINGS`, currently v1.13.3 `wings_linux_amd64`). It is copied to `/usr/local/bin/wings` only after the pinned SHA256 matches. Docker is the game-container runtime, installed from the distro archive when `docker` is missing.

| Path | Role |
|------|------|
| `/usr/local/bin/wings` | Wings binary |
| `/etc/pterodactyl` | Configuration directory |
| `/etc/pterodactyl/config.yml` | Node config from **your** panel |
| `/etc/systemd/system/wings.service` | Branded unit from `systemd/wings.service.template` |
| `/var/lib/pterodactyl/volumes` | Game volume data |

Default Wings API port **8080** and SFTP port **2022** are warnings if they are already listening. They are not a second panel. Disk below 10 GiB free on `/` is a warning.

TLS is manual. Put the certificate paths your panel wrote into `config.yml`. This package has no automatic certificate helper.

When the service is actually started, the local health check talks only to `127.0.0.1`. It does not use GlassHosting's servers to decide whether your node is up. Install-only mode does not start the service and does not pretend your panel accepted the node.

## Operator flow

1. Verify `SHA256SUMS` (see [Before you run it](#before-you-run-it)).
2. Dry-run first. This does not change the host:

```bash
sudo bash install.sh --dry-run --enroll \
  --panel-url 'https://YOUR_PANEL_URL' \
  --node-token 'YOUR_NODE_TOKEN' \
  --node-id 'YOUR_NODE_ID'
```

Replace the placeholders before a real enroll. A placeholder URL or token refuses enrollment rather than guessing a GlassHosting host.

3. On the host (root), either paste the panel configuration file:

```bash
sudo bash install.sh --enroll --config /root/wings-config.yml \
  --panel-url 'https://panel.example.invalid'
```

or let Wings write it from your panel's node id and token:

```bash
sudo bash install.sh --enroll \
  --panel-url 'https://panel.example.invalid' \
  --node-token 'paste-the-token-from-your-panel' \
  --node-id '1'
```

`panel.example.invalid` is a stand-in. Use the URL **your** panel shows. Prefer `--config` so the node token is not on the process list.

4. Install Wings without enrolling yet:

```bash
sudo bash install.sh --install-only
```

The unit is installed and not started. Enrollment is skipped. No GlassHosting URL is written in its place. The placeholder `config.yml` uses `YOUR_PANEL_URL` and `YOUR_NODE_TOKEN` until you replace it.

5. Confirm locally (after a real enroll started the service): the `wings` unit is active, and `https://127.0.0.1:8080/api/system` answers (an authentication challenge counts as success). Then confirm the node looks online **in your panel**.

### Try a server on your panel

On **your** panel, on **your** node:

1. Create a sandbox server (a small vanilla or Paper egg is enough).
2. Allocate a port from **your** node's pool.
3. Start it, open the console, upload a small file, and restart.
4. That confirms power, files, and console on your node only.

Do not copy server records you do not own into your panel, and do not point allocations at GlassHosting addresses. This free path is not GlassHosting capacity. You do not need WHMCS for the sandbox.

## If the installer refuses

You will see `INSTALLER_REFUSE` and a non-zero exit. GlassHosting-managed servers you do not own also print `REFUSED: GlassHosting-managed servers you do not own`. A refused panel address also prints `ENROLL REMOTE REFUSE`. Nothing is installed and nothing is enrolled.

Typical causes: the panel URL is a GlassHosting production panel, or the configuration you pasted names servers you do not own. Point the installer at your own panel, or run `--install-only` with those values removed from the environment and the flags.

`--dry-run` is safe while you check. The checks under `tests/` do not need a GlassHosting panel.

## Feedback

Support for this package is the documentation on this page.

- GitHub Discussions: category `free-ggp`
- GitHub Issues: label `free-ggp`
- Email: sales@glasshosting.com

## What a successful install means

Wings is on your machine. If you enrolled, it points at your panel.

- It does not add capacity on GlassHosting.
- It does not connect this node to a GlassHosting production panel.
- It is not WHMCS.
- It does not include a demo panel.

A successful DIY install is only a successful DIY install.

## Checks

From the repository root, with no GlassHosting panel:

```bash
bash packaging/free/tests/refuse_unowned_servers.sh
```

`make test` and `go test ./...` run the same checks. `--dry-run` is what they use. They set `GGP_FREE_FORBID_MUTATE=1` so a bug cannot change the host.

## Files

| File | Role |
|------|------|
| `install.sh` | Installer entrypoint |
| `deny/refused-servers.json` | Server identifiers the installer refuses. Do not copy them into your panel. |
| `deny/refuse-remotes.txt` | Panel addresses the installer refuses |
| `systemd/wings.service.template` | Branded `wings.service` |
| `brand/banner.txt` | Log banner |
| `upstream/WINGS` | Pinned Wings version, GitHub URL, SHA256 |
| `ATTRIBUTION.md` | Glasshouse wrapper credit and upstream Wings credit |
| `SHA256SUMS` | Checksums. Verify them before you run the installer. |
| `tests/refuse_unowned_servers.sh` | Checks that refused inputs are rejected |
