#!/usr/bin/env bash
# glassgamepanel-wings-free
# Glasshouse Holding Group / GlassHosting / GlassGamePanel
# DIY Wings installer for an operator-owned GlassGamePanel node.
# Refuses GlassHosting-managed servers and GlassHosting production panel addresses.
# Verify SHA256SUMS before run. Config path: /etc/pterodactyl
set -euo pipefail
umask 077

TMPFILES=()
cleanup() {
  local f
  [[ ${#TMPFILES[@]} -eq 0 ]] && return 0
  for f in "${TMPFILES[@]}"; do
    rm -f "$f"
  done
}
trap cleanup EXIT

ENV_SNAPSHOT=$(mktemp)
TMPFILES+=("$ENV_SNAPSHOT")
env >"$ENV_SNAPSHOT"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DENY_JSON="${ROOT}/deny/refused-servers.json"
REFUSE_FILE="${ROOT}/deny/refuse-remotes.txt"
BANNER_FILE="${ROOT}/brand/banner.txt"
UNIT_TEMPLATE="${ROOT}/systemd/wings.service.template"
UPSTREAM_FILE="${ROOT}/upstream/WINGS"
VERSION_FILE="${ROOT}/VERSION"

DRY_RUN=0
ENROLL=0
INSTALL_ONLY=0
WANT_HELP=0
WANT_VERSION=0
CONFIG_FILE=""
STDIN_CONFIG=""
FLAG_PANEL_URL=""
FLAG_REMOTE=""
FLAG_NODE_TOKEN=""
FLAG_NODE_ID=""
API_PORT="${API_PORT:-8080}"
SFTP_PORT="${SFTP_PORT:-2022}"
PANEL=""
NODE_TOKEN=""
NODE_ID=""
VERSION=""
ARTIFACT=""
WINGS_VERSION=""
WINGS_URL=""
WINGS_SHA256=""

CORPUS=""
JOINED=""
soft_uuid=0
soft_sid=0
soft_ext=0
soft_ct=0
soft_attest=0
soft_chi=0
remote_hit=0
demo_hit=0

SID_ALT='43|46|47|48|49|99|100|101'
# external_id pairing from the OpenAPI catalog (not a second UUID list).
EXT_ALT='30|43|47|48|53|70|71|72'
CT_ALT='210|211|1220'

refuse_now() {
  local kind="$1"
  shift
  echo "INSTALLER_REFUSE"
  case "$kind" in
    soft) echo "REFUSED: GlassHosting-managed servers you do not own" ;;
    remote) echo "ENROLL REMOTE REFUSE" ;;
    demo) echo "DEMO GGP REMOTE REFUSE" ;;
    *) echo "INSTALLER FAIL-CLOSED" ;;
  esac
  if [[ $# -gt 0 ]]; then
    printf '%s\n' "$@"
  fi
  echo "DIY-only: operator-owned GlassGamePanel. This installer will not substitute a GlassHosting URL."
  echo "No Wings install, enroll, or config write was performed."
  exit 2
}

print_banner() {
  if [[ ! -r "$BANNER_FILE" ]]; then
    echo "INSTALLER_REFUSE"
    echo "brand banner missing; fail-closed"
    echo "No Wings install, enroll, or config write was performed."
    exit 2
  fi
  cat "$BANNER_FILE"
}

load_version() {
  if [[ ! -r "$VERSION_FILE" ]]; then
    refuse_now other "VERSION file missing; fail-closed"
  fi
  VERSION="$(tr -d '[:space:]' <"$VERSION_FILE")"
  if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    refuse_now other "VERSION file is not a dotted version; fail-closed"
  fi
  ARTIFACT="glassgamepanel-wings-free-v${VERSION}"
  if ! grep -q -F "$ARTIFACT" "$BANNER_FILE"; then
    refuse_now other "brand banner does not name ${ARTIFACT}; fail-closed"
  fi
}

verify_fragment() {
  if [[ ! -r "$DENY_JSON" || ! -r "$REFUSE_FILE" ]]; then
    refuse_now other "deny fragment or refuse-remotes list missing; fail-closed"
  fi
  local uuids=() u s line
  while IFS= read -r u; do
    [[ -n "$u" ]] && uuids+=("$u")
  done < <(grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' "$DENY_JSON" || true)
  if [[ ${#uuids[@]} -ne 8 ]]; then
    refuse_now other "deny fragment uuid set incomplete; fail-closed"
  fi
  line="$(grep -E '"sids"' "$DENY_JSON" || true)"
  for s in 43 46 47 48 49 99 100 101; do
    if ! printf '%s\n' "$line" | grep -E -q "(^|[^0-9])${s}([^0-9]|$)"; then
      refuse_now other "deny fragment missing sid ${s}; fail-closed"
    fi
  done
  line="$(grep -E '"whmcs_cts"' "$DENY_JSON" || true)"
  for s in 210 211 1220; do
    if ! printf '%s\n' "$line" | grep -E -q "(^|[^0-9])${s}([^0-9]|$)"; then
      refuse_now other "deny fragment missing whmcs ct ${s}; fail-closed"
    fi
  done
}

load_upstream() {
  if [[ ! -r "$UPSTREAM_FILE" ]]; then
    refuse_now other "pinned wings upstream file missing; fail-closed"
  fi
  WINGS_VERSION="$(sed -n 's/^version=//p' "$UPSTREAM_FILE" | head -n1)"
  WINGS_URL="$(sed -n 's/^url=//p' "$UPSTREAM_FILE" | head -n1)"
  WINGS_SHA256="$(sed -n 's/^sha256=//p' "$UPSTREAM_FILE" | head -n1 | tr '[:upper:]' '[:lower:]')"
  if [[ -z "$WINGS_VERSION" || ! "$WINGS_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    refuse_now other "pinned wings checksum missing; fail-closed"
  fi
  case "$WINGS_URL" in
    https://github.com/pterodactyl/wings/releases/download/*/wings_linux_amd64) ;;
    *) refuse_now other "pinned wings URL is not the GitHub linux amd64 asset; fail-closed" ;;
  esac
  if printf '%s' "$WINGS_URL" | grep -q -i 'glasshosting'; then
    refuse_now remote "pinned wings URL must not be a GlassHosting host"
  fi
}

add_supplied_file() {
  local p="$1"
  [[ -n "$p" ]] || return 0
  if [[ "$p" == "-" ]]; then
    if [[ -t 0 ]]; then
      refuse_now other "config paste on stdin is empty; fail-closed"
    fi
    STDIN_CONFIG="$(mktemp)"
    TMPFILES+=("$STDIN_CONFIG")
    cat >"$STDIN_CONFIG"
    cat "$STDIN_CONFIG" >>"$CORPUS"
    return 0
  fi
  if [[ ! -e "$p" ]]; then
    return 0
  fi
  if [[ -d "$p" ]]; then
    refuse_now other "supplied path is a directory; fail-closed"
  fi
  if [[ ! -f "$p" ]]; then
    refuse_now other "supplied path is not a readable file; fail-closed"
  fi
  if [[ ! -r "$p" ]]; then
    refuse_now other "supplied file is not readable; fail-closed"
  fi
  local sz
  sz="$(stat -c '%s' "$p")"
  if [[ "$sz" -gt 2097152 ]]; then
    refuse_now other "supplied file too large to scan; fail-closed"
  fi
  cat "$p" >>"$CORPUS" || refuse_now other "supplied file could not be read; fail-closed"
}

maybe_add_supplied_file() {
  local p="$1"
  [[ -n "$p" && -e "$p" ]] || return 0
  add_supplied_file "$p"
}

collect_inputs() {
  CORPUS="$(mktemp)"
  TMPFILES+=("$CORPUS")
  : >"$CORPUS"
  local i=0 a next
  while [[ $i -lt $# ]]; do
    a="${@:$((i + 1)):1}"
    printf '%s\n' "$a" >>"$CORPUS"
    case "$a" in
      --config)
        next="${@:$((i + 2)):1}"
        add_supplied_file "$next"
        ;;
      --config=*)
        add_supplied_file "${a#--config=}"
        ;;
      --*=*)
        maybe_add_supplied_file "${a#*=}"
        ;;
      -*)
        ;;
      *)
        maybe_add_supplied_file "$a"
        ;;
    esac
    i=$((i + 1))
  done
  cat "$ENV_SNAPSHOT" >>"$CORPUS"
  if [[ -n "${GGP_CONFIG_PASTE:-}" ]]; then
    printf '%s\n' "$GGP_CONFIG_PASTE" >>"$CORPUS"
  fi
  if [[ -n "${GGP_CONFIG_FILE:-}" ]]; then
    add_supplied_file "$GGP_CONFIG_FILE"
  fi
  if [[ -n "${GGP_FREE_OS_RELEASE:-}" ]]; then
    add_supplied_file "$GGP_FREE_OS_RELEASE"
  fi
}

normalize_joined() {
  local norm tmp i
  norm="$(mktemp)"
  JOINED="$(mktemp)"
  TMPFILES+=("$norm" "$JOINED")
  tr '[:upper:]' '[:lower:]' <"$CORPUS" | sed 's/\r//g' >"$norm"
  for i in 1 2 3; do
    tmp="$(mktemp)"
    sed -e 's/%25/%/g' -e 's/%2d/-/g' -e 's/%2e/./g' -e 's/%3a/:/g' -e 's/%2f/\//g' -e 's/%3d/=/g' "$norm" >"$tmp"
    mv "$tmp" "$norm"
  done
  tr '\n' ' ' <"$norm" >"$JOINED"
  printf '\n' >>"$JOINED"
}

reset_hits() {
  soft_uuid=0
  soft_sid=0
  soft_ext=0
  soft_ct=0
  soft_attest=0
  soft_chi=0
  remote_hit=0
  demo_hit=0
}

scan_bracket_list() {
  local key="$1" kind="$2" rest inside tok
  rest="$(cat "$JOINED")"
  while [[ "$rest" =~ ${key}\"?[[:space:]]*[:=][[:space:]]*\[([^]]*)\] ]]; do
    inside="${BASH_REMATCH[1]}"
    for tok in $(printf '%s' "$inside" | tr -cs '0-9' ' '); do
      case "${kind}:${tok}" in
        sid:43|sid:46|sid:47|sid:48|sid:49|sid:99|sid:100|sid:101) soft_sid=1 ;;
        ext:30|ext:43|ext:47|ext:48|ext:53|ext:70|ext:71|ext:72) soft_ext=1 ;;
        ct:210|ct:211|ct:1220) soft_ct=1 ;;
      esac
    done
    rest="${rest#*"${BASH_REMATCH[0]}"}"
  done
}

scan_joined() {
  local u line ip re
  reset_hits
  while IFS= read -r u; do
    [[ -n "$u" ]] || continue
    u="$(printf '%s' "$u" | tr '[:upper:]' '[:lower:]')"
    if grep -F -q "$u" "$JOINED"; then
      soft_uuid=1
    fi
  done < <(grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' "$DENY_JSON" || true)

  local sid_key sid_flag ext_key ext_flag ct_key ct_flag ct_word
  sid_key="(^|[^a-z0-9])(sids|sid|wings_sid|server_sid|glass_sid)\"?[[:space:]]*[=:][[:space:]]*\"?(${SID_ALT})([^0-9]|\$)"
  sid_flag="(^|[[:space:]])(--sid|--wings-sid|--server-sid|--glass-sid)[[:space:]=]+\"?(${SID_ALT})([^0-9]|\$)"
  ext_key="(^|[^a-z0-9])external[_-]?ids?\"?[[:space:]]*[=:][[:space:]]*\"?(${EXT_ALT})([^0-9]|\$)"
  ext_flag="(^|[[:space:]])(--external-id|--external_id)[[:space:]=]+\"?(${EXT_ALT})([^0-9]|\$)"
  ct_key="(^|[^a-z0-9])(whmcs[_-]?cts|whmcs[_-]?ct|whmcs[_-]?service[_-]?ids|whmcs[_-]?service[_-]?id)\"?[[:space:]]*[=:][[:space:]]*\"?(ct[-_ ]?)?(${CT_ALT})([^0-9]|\$)"
  ct_flag="(^|[[:space:]])(--whmcs-ct|--whmcs-service-id)[[:space:]=]+\"?(ct[-_ ]?)?(${CT_ALT})([^0-9]|\$)"
  ct_word="(^|[^a-z0-9])ct[-_ ]?(${CT_ALT})([^0-9]|\$)"

  if grep -E -q "$sid_key" "$JOINED" || grep -E -q "$sid_flag" "$JOINED"; then
    soft_sid=1
  fi
  if grep -E -q "$ext_key" "$JOINED" || grep -E -q "$ext_flag" "$JOINED"; then
    soft_ext=1
  fi
  if grep -E -q "$ct_key" "$JOINED" || grep -E -q "$ct_flag" "$JOINED" || grep -E -q "$ct_word" "$JOINED"; then
    soft_ct=1
  fi
  scan_bracket_list 'sids' sid
  scan_bracket_list 'external_ids' ext
  scan_bracket_list 'whmcs_cts' ct
  scan_bracket_list 'whmcs-cts' ct

  # Marker only. Operators do not see this pattern. It still refuses pasted names for GlassHosting-managed servers.
  if grep -E -q 'include_soft_launch|include-soft-launch|founder_yes_attestation_id|founder-yes-attestation-id|soft[-_]launch|softlaunch|soft[[:space:]]+launch' "$JOINED"; then
    soft_attest=1
  fi
  if grep -E -q '(^|[^0-9])45\.45\.239\.7([^0-9]|$)' "$JOINED"; then
    soft_chi=1
    remote_hit=1
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      re="(^|[^0-9])$(printf '%s' "$line" | sed 's/\./\\./g')([^0-9]|\$)"
      if grep -E -q "$re" "$JOINED"; then
        remote_hit=1
        if [[ "$line" == "45.45.239.7" ]]; then
          soft_chi=1
        fi
      fi
    elif grep -F -q "$line" "$JOINED"; then
      remote_hit=1
    fi
  done <"$REFUSE_FILE"

  if grep -E -q '(^|[^0-9])10\.99\.0\.[0-9]{1,3}([^0-9]|$)' "$JOINED"; then
    remote_hit=1
  fi
  if grep -E -q '(^|[^a-z0-9])ct[-_ ]?316([^0-9]|$)' "$JOINED"; then
    remote_hit=1
  fi
  if grep -E -q '(^|[[:space:]])(--demo|--demo-ggp|--demo-remote)([[:space:]=]|$)' "$JOINED"; then
    demo_hit=1
  fi
  if grep -E -q '(^|[^a-z0-9])(demo_ggp_url|demo_panel_url|ggp_demo_remote)=' "$JOINED"; then
    demo_hit=1
  fi

  local messages=()
  local kind=""
  if [[ "$soft_uuid" == 1 || "$soft_sid" == 1 || "$soft_ext" == 1 || "$soft_ct" == 1 || "$soft_attest" == 1 || "$soft_chi" == 1 ]]; then
    kind="soft"
    [[ "$soft_uuid" == 1 ]] && messages+=("marker class: uuid")
    [[ "$soft_sid" == 1 ]] && messages+=("marker class: sid")
    [[ "$soft_ext" == 1 ]] && messages+=("marker class: external_id")
    [[ "$soft_ct" == 1 ]] && messages+=("marker class: whmcs_ct")
    [[ "$soft_attest" == 1 ]] && messages+=("marker class: attestation")
    [[ "$soft_chi" == 1 ]] && messages+=("marker class: glasshosting-address")
  fi
  if [[ "$demo_hit" == 1 ]]; then
    [[ -z "$kind" ]] && kind="demo"
    messages+=("a demo panel remote is not available")
  fi
  if [[ "$remote_hit" == 1 ]]; then
    [[ -z "$kind" ]] && kind="remote"
    messages+=("ENROLL REMOTE REFUSE")
  fi
  if [[ -n "$kind" ]]; then
    refuse_now "$kind" "${messages[@]}"
  fi
}

usage() {
  cat <<EOF
${ARTIFACT}
Glasshouse Holding Group / GlassHosting / GlassGamePanel
Free Wings one-click — DIY operator-owned GlassGamePanel only.

Usage:
  install.sh --dry-run [--enroll --panel-url URL --node-token TOKEN --node-id ID]
  install.sh --install-only
  install.sh --enroll --config /path/to/config.yml
  install.sh --help

Verify SHA256SUMS in this directory before you run the installer.

The installer refuses GlassHosting production panel addresses and configuration
that names GlassHosting-managed servers you do not own. It will not fill in a
GlassHosting URL.

Placeholders only: YOUR_PANEL_URL and YOUR_NODE_TOKEN.
Config path: /etc/pterodactyl
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)
        WANT_HELP=1
        shift
        ;;
      --version)
        WANT_VERSION=1
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      --install-only)
        INSTALL_ONLY=1
        shift
        ;;
      --enroll)
        ENROLL=1
        shift
        ;;
      --config)
        [[ $# -ge 2 ]] || refuse_now other "missing value for --config"
        CONFIG_FILE="$2"
        shift 2
        ;;
      --config=*)
        CONFIG_FILE="${1#*=}"
        shift
        ;;
      --panel-url)
        [[ $# -ge 2 ]] || refuse_now other "missing value for --panel-url"
        FLAG_PANEL_URL="$2"
        shift 2
        ;;
      --panel-url=*)
        FLAG_PANEL_URL="${1#*=}"
        shift
        ;;
      --remote)
        [[ $# -ge 2 ]] || refuse_now other "missing value for --remote"
        FLAG_REMOTE="$2"
        shift 2
        ;;
      --remote=*)
        FLAG_REMOTE="${1#*=}"
        shift
        ;;
      --node-token)
        [[ $# -ge 2 ]] || refuse_now other "missing value for --node-token"
        FLAG_NODE_TOKEN="$2"
        shift 2
        ;;
      --node-token=*)
        FLAG_NODE_TOKEN="${1#*=}"
        shift
        ;;
      --node-id)
        [[ $# -ge 2 ]] || refuse_now other "missing value for --node-id"
        FLAG_NODE_ID="$2"
        shift 2
        ;;
      --node-id=*)
        FLAG_NODE_ID="${1#*=}"
        shift
        ;;
      --api-port)
        [[ $# -ge 2 ]] || refuse_now other "missing value for --api-port"
        API_PORT="$2"
        shift 2
        ;;
      --api-port=*)
        API_PORT="${1#*=}"
        shift
        ;;
      --sftp-port)
        [[ $# -ge 2 ]] || refuse_now other "missing value for --sftp-port"
        SFTP_PORT="$2"
        shift 2
        ;;
      --sftp-port=*)
        SFTP_PORT="${1#*=}"
        shift
        ;;
      --demo|--demo-ggp|--demo-remote)
        refuse_now demo "demo GGP remote is hard-disabled for day-1"
        ;;
      --)
        shift
        if [[ $# -gt 0 ]]; then
          refuse_now other "unexpected argument"
        fi
        ;;
      -*)
        refuse_now other "unknown flag: $1"
        ;;
      *)
        refuse_now other "unexpected argument"
        ;;
    esac
  done
}

snapshot_value() {
  local key="$1"
  sed -n "s/^${key}=//p" "$ENV_SNAPSHOT" | head -n1
}

add_unique() {
  local v="$1" x
  [[ -n "$v" ]] || return 0
  if [[ ${#unique[@]} -gt 0 ]]; then
    for x in "${unique[@]}"; do
      [[ "$x" == "$v" ]] && return 0
    done
  fi
  unique+=("$v")
}

pick_one() {
  unique=()
  local v
  for v in "$@"; do
    add_unique "$v"
  done
  if [[ ${#unique[@]} -gt 1 ]]; then
    return 1
  fi
  if [[ ${#unique[@]} -eq 1 ]]; then
    printf '%s' "${unique[0]}"
  fi
  return 0
}

valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 1
  return 0
}

url_host() {
  local u
  u="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$u" in
    http://*|https://*) ;;
    *)
      printf '%s' ""
      return 0
      ;;
  esac
  u="${u#*://}"
  u="${u%%/*}"
  u="${u%%\?*}"
  u="${u##*@}"
  u="${u%%:*}"
  printf '%s' "$u"
}

resolve_mode() {
  if [[ "$ENROLL" == 1 && "$INSTALL_ONLY" == 1 ]]; then
    refuse_now other "--enroll and --install-only conflict. No GlassHosting URL is substituted."
  fi
  if ! valid_port "$API_PORT" || ! valid_port "$SFTP_PORT"; then
    refuse_now other "api/sftp port must be an integer from 1 to 65535"
  fi

  local chosen token_chosen id_chosen
  if ! chosen="$(pick_one "$FLAG_PANEL_URL" "$FLAG_REMOTE" "$(snapshot_value PANEL_URL)" "$(snapshot_value REMOTE)")"; then
    refuse_now remote "multiple panel URLs disagree. This installer will not substitute a GlassHosting URL."
  fi
  PANEL="$chosen"
  if ! token_chosen="$(pick_one "$FLAG_NODE_TOKEN" "$(snapshot_value NODE_TOKEN)" "$(snapshot_value WINGS_NODE_TOKEN)")"; then
    refuse_now other "multiple node tokens disagree. No token was written."
  fi
  NODE_TOKEN="$token_chosen"
  if ! id_chosen="$(pick_one "$FLAG_NODE_ID" "$(snapshot_value NODE_ID)")"; then
    refuse_now other "multiple node ids disagree."
  fi
  NODE_ID="$id_chosen"

  if [[ -z "$CONFIG_FILE" ]]; then
    CONFIG_FILE="$(snapshot_value GGP_CONFIG_FILE)"
  fi
  if [[ "$CONFIG_FILE" == "-" ]]; then
    CONFIG_FILE="$STDIN_CONFIG"
  fi
  if [[ -n "$CONFIG_FILE" && ! -f "$CONFIG_FILE" ]]; then
    refuse_now other "config file not found. No GlassHosting URL is substituted."
  fi

  local have_enroll_input=0
  if [[ -n "$PANEL" || -n "$NODE_TOKEN" || -n "$CONFIG_FILE" ]]; then
    have_enroll_input=1
  fi
  if [[ "$INSTALL_ONLY" == 1 ]]; then
    ENROLL=0
  elif [[ "$ENROLL" == 0 && "$have_enroll_input" == 1 ]]; then
    ENROLL=1
  fi

  if [[ "$ENROLL" == 1 ]]; then
    if [[ -z "$PANEL" && -z "$CONFIG_FILE" ]]; then
      refuse_now remote "enrollment needs YOUR_PANEL_URL. This installer will not substitute a GlassHosting URL."
    fi
    if [[ -n "$PANEL" ]]; then
      local scheme host
      scheme="$(printf '%s' "$PANEL" | tr '[:upper:]' '[:lower:]')"
      case "$scheme" in
        http://*|https://*) ;;
        *) refuse_now remote "panel URL must be http or https. This installer will not substitute a GlassHosting URL." ;;
      esac
      host="$(url_host "$PANEL")"
      case "$host" in
        your_panel_url|"")
          refuse_now remote "panel URL is still the YOUR_PANEL_URL placeholder. This installer will not substitute a GlassHosting URL."
          ;;
      esac
    fi
    if [[ -z "$CONFIG_FILE" ]]; then
      local token_lc
      token_lc="$(printf '%s' "$NODE_TOKEN" | tr '[:upper:]' '[:lower:]')"
      case "$token_lc" in
        ""|your_node_token|your_token|changeme)
          refuse_now other "enrollment needs a node token from YOUR panel (or --config). YOUR_NODE_TOKEN is a placeholder. No GlassHosting token is substituted."
          ;;
      esac
      if [[ -z "$NODE_ID" ]]; then
        refuse_now other "enrollment via token needs --node-id from YOUR panel, or pass --config from the panel Configuration tab."
      fi
    fi
  fi
}

load_os() {
  local f="/etc/os-release" id ver arch
  if [[ "$DRY_RUN" == 1 && -n "${GGP_FREE_OS_RELEASE:-}" && -r "${GGP_FREE_OS_RELEASE}" ]]; then
    f="${GGP_FREE_OS_RELEASE}"
  fi
  if [[ ! -r "$f" ]]; then
    echo "unsupported OS: cannot read os-release"
    return 1
  fi
  id="$(sed -n 's/^ID=//p' "$f" | head -n1 | tr -d '"' | tr '[:upper:]' '[:lower:]')"
  ver="$(sed -n 's/^VERSION_ID=//p' "$f" | head -n1 | tr -d '"')"
  arch="$(uname -m)"
  echo "os: ${id} ${ver}"
  echo "arch: ${arch}"
  if [[ "$arch" != "x86_64" ]]; then
    echo "unsupported arch: want x86_64"
    return 1
  fi
  case "$id" in
    ubuntu)
      case "$ver" in
        22.04|24.04)
          echo "os support: ubuntu ${ver} primary"
          return 0
          ;;
        *)
          echo "unsupported ubuntu ${ver}: want 22.04 or 24.04"
          return 1
          ;;
      esac
      ;;
    debian)
      case "$ver" in
        12)
          echo "os support: debian 12 optional; package docker.io (no name drift vs Ubuntu 22.04/24.04)"
          return 0
          ;;
        *)
          echo "unsupported debian ${ver}: want 12"
          return 1
          ;;
      esac
      ;;
    *)
      echo "unsupported OS: ${id:-unknown}. Supported systems are Ubuntu 22.04/24.04 and Debian 12, x86_64."
      return 1
      ;;
  esac
}

warn_disk() {
  local avail_kb
  avail_kb="$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}' || true)"
  if [[ -z "${avail_kb}" || ! "$avail_kb" =~ ^[0-9]+$ ]]; then
    echo "warn: could not read free disk on /"
    return 0
  fi
  if [[ "$avail_kb" -lt 10485760 ]]; then
    echo "warn: free disk on / is below 10 GiB (${avail_kb} KiB). Continuing."
  else
    echo "disk: free space on / meets the 10 GiB soft minimum"
  fi
}

warn_ports() {
  local p
  if ! command -v ss >/dev/null 2>&1; then
    echo "warn: ss not available; skipped listen check for ${API_PORT}/tcp and ${SFTP_PORT}/tcp"
    return 0
  fi
  for p in "$API_PORT" "$SFTP_PORT"; do
    if ss -ltn | awk '{print $4}' | grep -E -q "[:.]${p}\$"; then
      echo "warn: port ${p}/tcp appears to be listening. Continuing."
    fi
  done
}

print_plan() {
  echo "dry-run: preflight PASS"
  echo "dry-run: no host mutate"
  echo "plan: install distro package docker.io when docker is missing (not an unsigned curl|bash)"
  echo "plan: install wings ${WINGS_VERSION} to /usr/local/bin/wings after sha256 ${WINGS_SHA256}"
  echo "plan: install systemd unit wings.service from the branded template"
  echo "plan: config directory /etc/pterodactyl"
  if [[ "$ENROLL" == 1 ]]; then
    if [[ -n "$PANEL" ]]; then
      echo "plan: enroll DIY remote host $(url_host "$PANEL") (token redacted)"
    else
      echo "plan: enroll from operator config file (token redacted)"
    fi
    echo "plan: healthcheck local only at https://127.0.0.1:${API_PORT}/api/system"
  else
    echo "Enrollment skipped. No GlassHosting URL is substituted."
    echo "plan: wings.service is installed but not started until you enroll"
  fi
  echo "H4 N/A: health check does not use GlassHosting-managed servers"
  echo "H5: Glasshouse Holding Group / GlassHosting / GlassGamePanel"
  echo "This install is your Wings node only. It does not add GlassHosting capacity."
  echo "artifact: ${ARTIFACT}"
}

run_mutate() {
  if [[ "${GGP_FREE_FORBID_MUTATE:-0}" == 1 ]]; then
    echo "INSTALLER_REFUSE"
    echo "host mutate blocked"
    echo "No Wings install, enroll, or config write was performed."
    exit 99
  fi
  if [[ -n "${GGP_FREE_MUTATE_PROOF:-}" ]]; then
    printf 'mutate\n' >>"${GGP_FREE_MUTATE_PROOF}"
  fi
  "$@"
}

write_placeholder_config() {
  local tmp
  tmp="$(mktemp)"
  TMPFILES+=("$tmp")
  cat >"$tmp" <<EOF
# GlassGamePanel free Wings — DIY placeholder.
# Replace this file with the Configuration tab from YOUR panel.
# Do not point it at GlassHosting.
app_name: GlassGamePanel
remote: "https://YOUR_PANEL_URL"
token_id: "YOUR_TOKEN_ID"
token: "YOUR_NODE_TOKEN"
api:
  host: 0.0.0.0
  port: ${API_PORT}
  ssl:
    enabled: false
  upload_limit: 100
system:
  data: /var/lib/pterodactyl/volumes
  sftp:
    bind_port: ${SFTP_PORT}
allowed_mounts: []
EOF
  run_mutate install -m 0600 "$tmp" /etc/pterodactyl/config.yml
}

install_for_real() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "root or sudo is required to install Wings. Refusing to mutate."
    echo "artifact: ${ARTIFACT}"
    exit 1
  fi
  if [[ -n "$CONFIG_FILE" ]]; then
    # Scan again immediately before any host change.
    CORPUS="$(mktemp)"
    TMPFILES+=("$CORPUS")
    cat "$CONFIG_FILE" >"$CORPUS"
    normalize_joined
    scan_joined
  fi
  export DEBIAN_FRONTEND=noninteractive
  run_mutate apt-get update
  if command -v docker >/dev/null 2>&1; then
    run_mutate apt-get install -y ca-certificates curl
  else
    run_mutate apt-get install -y ca-certificates curl docker.io
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemd is required for the wings unit. Refusing to claim success."
    exit 1
  fi
  run_mutate systemctl enable --now docker

  local tmp got
  tmp="$(mktemp)"
  TMPFILES+=("$tmp")
  run_mutate curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 --max-redirs 5 -o "$tmp" "$WINGS_URL"
  got="$(sha256sum "$tmp" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
  if [[ "$got" != "$WINGS_SHA256" ]]; then
    rm -f "$tmp"
    echo "wings checksum mismatch; binary not installed"
    exit 1
  fi
  run_mutate install -m 0755 "$tmp" /usr/local/bin/wings
  rm -f "$tmp"

  run_mutate install -d -m 0755 /etc/pterodactyl /var/lib/pterodactyl/volumes /var/run/wings
  run_mutate install -m 0644 "$UNIT_TEMPLATE" /etc/systemd/system/wings.service
  run_mutate systemctl daemon-reload

  if [[ -n "$CONFIG_FILE" ]]; then
    run_mutate install -m 0600 "$CONFIG_FILE" /etc/pterodactyl/config.yml
  elif [[ "$ENROLL" == 1 ]]; then
    run_mutate /usr/local/bin/wings configure --panel-url "$PANEL" --token "$NODE_TOKEN" --node "$NODE_ID"
  else
    write_placeholder_config
  fi

  if [[ "$ENROLL" == 1 ]]; then
    run_mutate systemctl enable --now wings
    healthcheck_local "$API_PORT"
    print_success enrolled
  else
    echo "H1/H2 skipped until you enroll and start wings."
    echo "H3 WARN: install-only, enroll later. No GlassHosting URL is substituted."
    echo "H4 N/A: health check does not use GlassHosting-managed servers"
    print_success install-only
  fi
}

# Local Wings API only. Does not treat GlassHosting-managed servers as proof the node is up.
healthcheck_local() {
  local port="$1" code
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "H1 FAIL: systemd is not available" >&2
    return 1
  fi
  if ! systemctl is-active --quiet wings; then
    echo "H1 FAIL: wings unit is not active" >&2
    return 1
  fi
  echo "H1 PASS: wings unit is active"
  code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:${port}/api/system" || true)"
  if [[ "$code" == "000" || -z "$code" ]]; then
    code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${port}/api/system" || true)"
  fi
  case "$code" in
    200|401|403)
      echo "H2 PASS: local wings API responded (${code})"
      ;;
    *)
      echo "H2 FAIL: local wings API http ${code}" >&2
      return 1
      ;;
  esac
  echo "H3: confirm the node in YOUR panel. This installer did not dial a panel."
  echo "H4 N/A: health check does not use GlassHosting-managed servers"
  echo "H5: Glasshouse Holding Group / GlassHosting / GlassGamePanel"
}
# end healthcheck_local

print_success() {
  local mode="$1"
  echo "GlassGamePanel free Wings installer finished (${mode})."
  echo "artifact: ${ARTIFACT}"
  echo "config: /etc/pterodactyl"
  echo "Create a sandbox server on YOUR panel and YOUR node only."
  echo "This install is your Wings node only. It does not add GlassHosting capacity."
  echo "Light pointers only (not required; no live Portal-to-Wings claim): GlassPortal, GlassProvision, MSP/GlassHosting."
}

main() {
  print_banner
  load_version
  verify_fragment
  load_upstream
  collect_inputs "$@"
  normalize_joined
  scan_joined
  parse_args "$@"
  if [[ "$WANT_HELP" == 1 ]]; then
    usage
    exit 0
  fi
  if [[ "$WANT_VERSION" == 1 ]]; then
    echo "$ARTIFACT"
    exit 0
  fi
  resolve_mode
  if ! load_os; then
    echo "Refusing to mutate on an unsupported OS or arch."
    exit 1
  fi
  warn_disk
  warn_ports
  if [[ "$DRY_RUN" == 1 ]]; then
    print_plan
    exit 0
  fi
  install_for_real
}

main "$@"
