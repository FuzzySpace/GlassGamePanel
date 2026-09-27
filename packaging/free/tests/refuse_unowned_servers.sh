#!/usr/bin/env bash
# Fixture tests for the free Wings installer.
# No GlassHosting panel. Dry-run only. Host mutate is forbidden.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FREE="$(cd "${HERE}/.." && pwd)"
ROOT="$(cd "${FREE}/../.." && pwd)"
INSTALL="${FREE}/install.sh"
FRAG="${FREE}/deny/refused-servers.json"

# Fixture runs must not depend on the executor host OS. CI is ubuntu-latest;
# local boxes may be newer Debian. Default a supported os-release when unset.
if [[ -z "${GGP_FREE_OS_RELEASE:-}" ]]; then
  _ggp_free_os_default="$(mktemp)"
  printf 'ID=ubuntu\nVERSION_ID=22.04\n' >"${_ggp_free_os_default}"
  export GGP_FREE_OS_RELEASE="${_ggp_free_os_default}"
  trap 'rm -f "${_ggp_free_os_default}"' EXIT
fi


failures=0
passes=0

say_pass() {
  passes=$((passes + 1))
  echo "PASS $*"
}

say_fail() {
  failures=$((failures + 1))
  echo "FAIL $*"
}

snapshot_host() {
  local p
  for p in /etc/pterodactyl /usr/local/bin/wings /etc/systemd/system/wings.service; do
    if [[ -e "$p" ]]; then
      stat -c '%n %F %i %s %Y' "$p"
    else
      echo "$p absent"
    fi
  done
}

HOST_BEFORE="$(snapshot_host)"

# Run the installer with a clean environment.
# Extra KEY=VALUE pairs come before the install.sh arguments.
# Usage: run_inst OUT ERR PROOF -- env assignments -- args...
run_inst() {
  local out="$1" err="$2" proof="$3"
  shift 3
  local -a env_kv=()
  local -a args=()
  local phase=0 item
  for item in "$@"; do
    if [[ "$item" == "--" && "$phase" -lt 2 ]]; then
      phase=$((phase + 1))
      continue
    fi
    if [[ "$phase" == 1 ]]; then
      env_kv+=("$item")
    elif [[ "$phase" == 2 ]]; then
      args+=("$item")
    else
      echo "run_inst: expected -- env -- args" >&2
      echo 99
      return 0
    fi
  done
  set +e
  local os_forward=()
  local has_os=0
  local kv
  for kv in "${env_kv[@]+"${env_kv[@]}"}"; do
    case "$kv" in
      GGP_FREE_OS_RELEASE=*) has_os=1 ;;
    esac
  done
  if [[ "$has_os" -eq 0 && -n "${GGP_FREE_OS_RELEASE:-}" ]]; then
    os_forward+=("GGP_FREE_OS_RELEASE=${GGP_FREE_OS_RELEASE}")
  fi
  env -i \
    PATH="${PATH}" \
    HOME="${HOME:-/tmp}" \
    LANG=C \
    LC_ALL=C \
    GGP_FREE_MUTATE_PROOF="${proof}" \
    GGP_FREE_FORBID_MUTATE=1 \
    "${os_forward[@]+"${os_forward[@]}"}" \
    "${env_kv[@]}" \
    bash "${INSTALL}" "${args[@]}" \
    >"${out}" 2>"${err}"
  local rc=$?
  set -e
  echo "$rc"
}

combined() {
  cat "$1" "$2"
}

expect_refuse() {
  local name="$1" need="$2"
  shift 2
  local out err proof rc blob
  out="$(mktemp)"
  err="$(mktemp)"
  proof="$(mktemp)"
  rc="$(run_inst "$out" "$err" "$proof" "$@")"
  blob="$(combined "$out" "$err")"
  local ok=1
  if [[ "$rc" == 0 ]]; then
    ok=0
    echo "  expected non-zero, got 0"
  fi
  if ! printf '%s\n' "$blob" | grep -q -F 'INSTALLER_REFUSE'; then
    ok=0
    echo "  missing INSTALLER_REFUSE"
  fi
  if ! printf '%s\n' "$blob" | grep -q -F "$need"; then
    ok=0
    echo "  missing phrase: $need"
  fi
  if printf '%s\n' "$blob" | grep -q -i -E 'soft[-_ ]launch|hard deny|estate|phase c|publish hold'; then
    ok=0
    echo "  operator output still uses internal wording"
  fi
  if [[ -s "$proof" ]]; then
    ok=0
    echo "  mutate proof was written"
  fi
  if printf '%s\n' "$blob" | grep -q -F 'host mutate blocked'; then
    ok=0
    echo "  reached mutate gate"
  fi
  if [[ "$ok" == 1 ]]; then
    say_pass "$name"
  else
    say_fail "$name"
    printf '%s\n' "$blob" | tail -n 40 | sed 's/^/  | /'
  fi
  rm -f "$out" "$err" "$proof"
}

expect_ok() {
  local name="$1" need="${2:-}"
  shift
  [[ -n "${need}" ]] && shift || true
  local out err proof rc blob
  out="$(mktemp)"
  err="$(mktemp)"
  proof="$(mktemp)"
  rc="$(run_inst "$out" "$err" "$proof" "$@")"
  blob="$(combined "$out" "$err")"
  local ok=1
  if [[ "$rc" != 0 ]]; then
    ok=0
    echo "  expected 0, got ${rc}"
  fi
  if printf '%s\n' "$blob" | grep -q -F 'INSTALLER_REFUSE'; then
    ok=0
    echo "  unexpected INSTALLER_REFUSE"
  fi
  if ! printf '%s\n' "$blob" | grep -q -F 'preflight PASS'; then
    ok=0
    echo "  missing preflight PASS"
  fi
  if [[ -n "$need" ]] && ! printf '%s\n' "$blob" | grep -q -F "$need"; then
    ok=0
    echo "  missing phrase: $need"
  fi
  if printf '%s\n' "$blob" | grep -q -i -E 'soft[-_ ]launch|hard deny|estate|phase c|publish hold'; then
    ok=0
    echo "  operator output still uses internal wording"
  fi
  if [[ -s "$proof" ]]; then
    ok=0
    echo "  mutate proof was written"
  fi
  if printf '%s\n' "$blob" | grep -q -F 'mock-node-token'; then
    ok=0
    echo "  node token leaked into output"
  fi
  if [[ "$ok" == 1 ]]; then
    say_pass "$name"
  else
    say_fail "$name"
    printf '%s\n' "$blob" | tail -n 40 | sed 's/^/  | /'
  fi
  rm -f "$out" "$err" "$proof"
}

expect_rc() {
  local name="$1" want="$2" need="$3"
  shift 3
  local out err proof rc blob
  out="$(mktemp)"
  err="$(mktemp)"
  proof="$(mktemp)"
  rc="$(run_inst "$out" "$err" "$proof" "$@")"
  blob="$(combined "$out" "$err")"
  local ok=1
  if [[ "$rc" != "$want" ]]; then
    ok=0
    echo "  expected ${want}, got ${rc}"
  fi
  if printf '%s\n' "$blob" | grep -q -F 'INSTALLER_REFUSE'; then
    ok=0
    echo "  unexpected INSTALLER_REFUSE"
  fi
  if ! printf '%s\n' "$blob" | grep -q -F "$need"; then
    ok=0
    echo "  missing phrase: $need"
  fi
  if printf '%s\n' "$blob" | grep -q -i -E 'soft[-_ ]launch|hard deny|estate|phase c|publish hold'; then
    ok=0
    echo "  operator output still uses internal wording"
  fi
  if [[ -s "$proof" ]]; then
    ok=0
    echo "  mutate proof was written"
  fi
  if [[ "$ok" == 1 ]]; then
    say_pass "$name"
  else
    say_fail "$name"
    printf '%s\n' "$blob" | tail -n 40 | sed 's/^/  | /'
  fi
  rm -f "$out" "$err" "$proof"
}

static_fail() {
  say_fail "$1"
  echo "  $2"
}

echo "== fragment identity =="
if cmp -s "${FRAG}" "${ROOT}/managed-inventory-deny.json" \
  && cmp -s "${FRAG}" "${ROOT}/internal/deny/managed-inventory-deny.json"; then
  say_pass "deny fragment matches the repository deny map"
else
  static_fail "deny fragment drifted from the repository deny map" "cmp failed"
fi

mapfile -t UUIDS < <(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "${FRAG}")
if [[ ${#UUIDS[@]} -ne 8 ]]; then
  static_fail "uuid count" "got ${#UUIDS[@]}"
fi

SIDS=(43 46 47 48 49 99 100 101)
CTS=(210 211 1220)

echo "== A1 uuid fixtures =="
i=0
for u in "${UUIDS[@]}"; do
  i=$((i + 1))
  expect_refuse "A1 env uuid ${i}" "REFUSED: GlassHosting-managed servers you do not own" -- "NOTES=${u}" -- --dry-run --install-only
  expect_refuse "A1 flag uuid ${i}" "marker class: uuid" -- -- --dry-run --install-only --node-token "${u}"
  cfg="$(mktemp)"
  printf 'remote: https://panel.operator.example\nserver_id: %s\n' "$u" >"$cfg"
  expect_refuse "A1 config uuid ${i}" "REFUSED: GlassHosting-managed servers you do not own" -- -- --dry-run --config "$cfg"
  rm -f "$cfg"
done
upper="$(printf '%s' "${UUIDS[0]}" | tr '[:lower:]' '[:upper:]')"
expect_refuse "A1 uppercase uuid" "marker class: uuid" -- "NOTES=${upper}" -- --dry-run --install-only

echo "== A2 sid fixtures =="
for s in "${SIDS[@]}"; do
  expect_refuse "A2 env sid ${s}" "marker class: sid" -- "SID=${s}" -- --dry-run --install-only
  expect_refuse "A2 flag sid ${s}" "marker class: sid" -- -- --dry-run --install-only --sid "${s}"
  cfg="$(mktemp)"
  printf 'sid: %s\nremote: https://panel.operator.example\n' "$s" >"$cfg"
  expect_refuse "A2 config sid ${s}" "marker class: sid" -- -- --dry-run --config "$cfg"
  rm -f "$cfg"
done
cfg="$(mktemp)"
printf 'sids: [43, 101]\n' >"$cfg"
expect_refuse "A2 sids array" "marker class: sid" -- -- --dry-run --config "$cfg"
rm -f "$cfg"

echo "== A3 whmcs ct fixtures =="
expect_refuse "A3 env ct 210" "marker class: whmcs_ct" -- "WHMCS_CT=210" -- --dry-run --install-only
expect_refuse "A3 flag ct 211" "marker class: whmcs_ct" -- -- --dry-run --install-only --whmcs-ct 211
cfg="$(mktemp)"
printf 'whmcs_service_id: 1220\n' >"$cfg"
expect_refuse "A3 config ct 1220" "marker class: whmcs_ct" -- -- --dry-run --config "$cfg"
rm -f "$cfg"
cfg="$(mktemp)"
printf 'notes: ct 210 nearby\n' >"$cfg"
expect_refuse "A3 prose ct 210" "marker class: whmcs_ct" -- -- --dry-run --config "$cfg"
rm -f "$cfg"
cfg="$(mktemp)"
printf 'whmcs_cts: [211, 1220]\n' >"$cfg"
expect_refuse "A3 whmcs_cts array" "marker class: whmcs_ct" -- -- --dry-run --config "$cfg"
rm -f "$cfg"
expect_refuse "A3 panel query ct" "marker class: whmcs_ct" -- -- --dry-run --panel-url 'https://panel.operator.example/?whmcs_ct=CT210'

echo "== A4 opt-in and refused address =="
expect_refuse "A4 managed-inventory flag true" "marker class: attestation" -- "include_soft_launch=true" -- --dry-run --install-only
expect_refuse "A4 managed-inventory flag false" "marker class: attestation" -- "include_soft_launch=false" -- --dry-run --help
expect_refuse "A4 attestation id" "marker class: attestation" -- "founder_yes_attestation_id=not-a-real-id" -- --dry-run --install-only
cfg="$(mktemp)"
printf 'notes: do not use soft launch inventory\n' >"$cfg"
expect_refuse "A4 managed-inventory phrase" "marker class: attestation" -- -- --dry-run --config "$cfg"
rm -f "$cfg"
expect_refuse "A4 refused address" "marker class: glasshosting-address" -- -- --dry-run --panel-url 'https://45.45.239.7:8080'

echo "== A5 production panel remotes =="
expect_refuse "A5 panel-api.glasshosting.com" "ENROLL REMOTE REFUSE" -- "PANEL_URL=https://panel-api.glasshosting.com" -- --dry-run --enroll
expect_refuse "A5 panel.glasshosting.com" "ENROLL REMOTE REFUSE" -- "PANEL_URL=https://panel.glasshosting.com/server" -- --dry-run
expect_refuse "A5 mixed-case panel host" "ENROLL REMOTE REFUSE" -- -- --dry-run --panel-url 'https://Panel.GlassHosting.com'
expect_refuse "A5 percent-encoded host" "ENROLL REMOTE REFUSE" -- -- --dry-run --panel-url 'https://panel%2eglasshosting%2ecom/node'
expect_refuse "A5 no silent fallback phrase" "will not substitute a GlassHosting URL" -- "PANEL_URL=https://panel-api.glasshosting.com/v1" -- --dry-run

echo "== A6 refused address remote =="
expect_refuse "A6 refused address remote" "ENROLL REMOTE REFUSE" -- -- --dry-run --remote 'http://45.45.239.7/'
cfg="$(mktemp)"
printf 'remote: https://45.45.239.7\n' >"$cfg"
expect_refuse "A6 refused address in config" "REFUSED: GlassHosting-managed servers you do not own" -- -- --dry-run --config "$cfg"
rm -f "$cfg"

echo "== A7 private hosts and addresses =="
expect_refuse "A7 refused test panel host" "ENROLL REMOTE REFUSE" -- -- --dry-run --panel-url 'https://panel-api-test.glasshosting.internal/v1'
expect_refuse "A7 refused test panel token" "ENROLL REMOTE REFUSE" -- -- --dry-run --panel-url 'https://panel.operator.example' --node-token 'panel-api-test'
expect_refuse "A7 10.99.0.40" "ENROLL REMOTE REFUSE" -- -- --dry-run --panel-url 'http://10.99.0.40:8080'
expect_refuse "A7 10.99.0.41 style" "ENROLL REMOTE REFUSE" -- -- --dry-run --remote 'http://10.99.0.41/'
expect_refuse "A7 refused host marker" "ENROLL REMOTE REFUSE" -- "NOTES=please use CT316" -- --dry-run --install-only
expect_refuse "A7 ct-316" "ENROLL REMOTE REFUSE" -- -- --dry-run --panel-url 'https://panel.operator.example/ct-316'
expect_refuse "A7 10.10.1.43" "ENROLL REMOTE REFUSE" -- -- --dry-run --panel-url 'http://10.10.1.43:8080'

echo "== A13 demo remote unavailable =="
expect_refuse "A13 --demo" "DEMO GGP REMOTE REFUSE" -- -- --dry-run --demo
expect_refuse "A13 DEMO_GGP_URL" "DEMO GGP REMOTE REFUSE" -- "DEMO_GGP_URL=https://panel.operator.example" -- --dry-run --install-only

echo "== external_id keyed match =="
expect_refuse "external_id 30" "marker class: external_id" -- -- --dry-run --external-id 30
cfg="$(mktemp)"
printf 'external_id: "43"\n' >"$cfg"
expect_refuse "external_id json 43" "marker class: external_id" -- -- --dry-run --config "$cfg"
rm -f "$cfg"

echo "== benign inputs stay clear =="
cfg="$(mktemp)"
cat >"$cfg" <<'EOF'
app_name: GlassGamePanel
remote: https://panel.operator.example
token_id: YOUR_TOKEN_ID
token: mock-node-token
api:
  host: 0.0.0.0
  port: 25566
system:
  sftp:
    bind_port: 2022
memory_mb: 43
extra_memory: 100
unrelated: 210
name: node-48
notes: sandbox on the operator panel
node_id: 1
EOF
expect_ok "benign config with ports and small integers" "dry-run: no host mutate" -- -- --dry-run --install-only --config "$cfg"
rm -f "$cfg"
expect_ok "A9 dry-run enroll mock panel" "plan: enroll DIY remote host panel.operator.example" -- -- --dry-run --enroll --panel-url 'https://panel.operator.example' --node-token 'mock-node-token' --node-id 1
expect_ok "--api-port 43 is not a sid" "preflight PASS" -- -- --dry-run --install-only --api-port 43
expect_ok "--node-id 1 is the operator node" "preflight PASS" -- -- --dry-run --enroll --panel-url 'https://panel.operator.example' --node-token 'mock-node-token' --node-id 1
expect_ok "install-only does not invent a remote" "Enrollment skipped. No GlassHosting URL is substituted." -- -- --dry-run --install-only
mem="$(mktemp)"
printf 'memory: 1220\nremote: https://panel.operator.example\n' >"$mem"
expect_ok "memory 1220 is not a ct marker" "preflight PASS" -- -- --dry-run --install-only --config "$mem"
rm -f "$mem"

echo "== mode and os =="
expect_refuse "enroll without url" "will not substitute a GlassHosting URL" -- -- --dry-run --enroll
expect_refuse "placeholder panel url" "YOUR_PANEL_URL placeholder" -- -- --dry-run --enroll --panel-url 'https://YOUR_PANEL_URL' --node-token 'mock-node-token' --node-id 1
expect_refuse "placeholder token" "YOUR_NODE_TOKEN is a placeholder" -- -- --dry-run --enroll --panel-url 'https://panel.operator.example' --node-token 'YOUR_NODE_TOKEN' --node-id 1
expect_refuse "disagreeing remotes" "ENROLL REMOTE REFUSE" -- "PANEL_URL=https://panel.operator.example" -- --dry-run --remote 'https://other.operator.example'
fedora="$(mktemp)"
printf 'ID=fedora\nVERSION_ID=40\n' >"$fedora"
expect_rc "unsupported os dry-run" 1 "unsupported OS" -- "GGP_FREE_OS_RELEASE=${fedora}" -- --dry-run --install-only
rm -f "$fedora"
deb="$(mktemp)"
printf 'ID=debian\nVERSION_ID=12\n' >"$deb"
expect_ok "debian 12 optional os" "package docker.io (no name drift vs Ubuntu 22.04/24.04)" -- "GGP_FREE_OS_RELEASE=${deb}" -- --dry-run --install-only
rm -f "$deb"
u22="$(mktemp)"
printf 'ID=ubuntu\nVERSION_ID=22.04\n' >"$u22"
expect_ok "ubuntu 22.04 primary" "os support: ubuntu 22.04 primary" -- "GGP_FREE_OS_RELEASE=${u22}" -- --dry-run --install-only
rm -f "$u22"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  case "${ID}:${VERSION_ID}" in
    ubuntu:22.04|ubuntu:24.04|debian:12)
      expect_ok "host os ${ID} ${VERSION_ID}" "os: ${ID} ${VERSION_ID}" -- "GGP_FREE_OS_RELEASE=" -- --dry-run --install-only
      ;;
    *)
      echo "SKIP host os ${ID} ${VERSION_ID} (unsupported on fixture host; CI covers ubuntu)"
      ;;
  esac
fi

# Real install (not dry-run) reads the host os-release. On unsupported hosts the
# installer fail-closes on OS before the root check; both are non-mutating refuses.
out="$(mktemp)"; err="$(mktemp)"; proof="$(mktemp)"
rc="$(run_inst "$out" "$err" "$proof" -- -- --install-only)"
blob="$(combined "$out" "$err")"
if [[ "$rc" != 0 ]] && [[ ! -s "$proof" ]] && {
  printf '%s\n' "$blob" | grep -q -F 'root or sudo is required' \
    || printf '%s\n' "$blob" | grep -q -F 'unsupported'
}; then
  say_pass "non-root real install does not mutate"
else
  say_fail "non-root real install does not mutate"
  printf '%s\n' "$blob" | tail -n 20 | sed 's/^/  | /'
fi
rm -f "$out" "$err" "$proof"

out="$(mktemp)"
err="$(mktemp)"
proof="$(mktemp)"
rc="$(run_inst "$out" "$err" "$proof" -- -- --help)"
blob="$(combined "$out" "$err")"
if [[ "$rc" == 0 ]] && printf '%s\n' "$blob" | grep -q -F 'servers you do not own' && printf '%s\n' "$blob" | grep -q -F 'Verify SHA256SUMS' && ! printf '%s\n' "$blob" | grep -q -F 'INSTALLER_REFUSE' && ! printf '%s\n' "$blob" | grep -q -i -E 'soft[-_ ]launch|hard deny|estate|phase c|publish hold'; then
  say_pass "--help is branded and not a refuse"
else
  say_fail "--help"
  printf '%s\n' "$blob" | tail -n 20 | sed 's/^/  | /'
fi
rm -f "$out" "$err" "$proof"

out="$(mktemp)"
err="$(mktemp)"
proof="$(mktemp)"
rc="$(run_inst "$out" "$err" "$proof" -- -- --version)"
blob="$(combined "$out" "$err")"
if [[ "$rc" == 0 ]] && printf '%s\n' "$blob" | grep -q -F 'glassgamepanel-wings-free-v0.1.0'; then
  say_pass "--version prints artifact name"
else
  say_fail "--version"
fi
rm -f "$out" "$err" "$proof"

pushd /tmp >/dev/null
out="$(mktemp)"
err="$(mktemp)"
proof="$(mktemp)"
rc="$(run_inst "$out" "$err" "$proof" -- -- --dry-run --install-only)"
blob="$(combined "$out" "$err")"
if [[ "$rc" == 0 ]] && printf '%s\n' "$blob" | grep -q -F 'preflight PASS'; then
  say_pass "dry-run from /tmp still finds the package"
else
  say_fail "dry-run from /tmp"
  printf '%s\n' "$blob" | tail -n 20 | sed 's/^/  | /'
fi
rm -f "$out" "$err" "$proof"
popd >/dev/null

big="$(mktemp)"
dd if=/dev/zero of="$big" bs=1024 count=3072 status=none
expect_refuse "oversized supplied file fail-closed" "supplied file too large to scan" -- -- --dry-run --config "$big"
rm -f "$big"

echo "== A8 credentials and A10-A13 static =="
if grep -R -n -E --exclude 'refuse_unowned_servers.sh' 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.|postgres(ql)?://[^[:space:]]+:[^[:space:]@]+@|mysql://[^[:space:]]+:[^[:space:]@]+@|AKIA[0-9A-Z]{16}' "${FREE}"; then
  static_fail "A8 credential literals" "pattern matched"
else
  say_pass "A8 no prod credential literals"
fi
if grep -n -E '^(PANEL_URL|REMOTE|NODE_TOKEN|WINGS_NODE_TOKEN)=https?://' "${INSTALL}"; then
  static_fail "A8 default remote assignment" "install.sh assigns a URL"
else
  say_pass "A8 installer does not default PANEL_URL"
fi
if grep -n -E 'PANEL_URL=.*glasshosting|REMOTE=.*glasshosting' "${INSTALL}"; then
  static_fail "A8 glasshosting default" "found"
else
  say_pass "A8 no GlassHosting URL default in install.sh"
fi

hc="$(awk '/^healthcheck_local\(\)/,/^# end healthcheck_local/' "${INSTALL}")"
if printf '%s\n' "$hc" | grep -E -q 'glasshosting|45\.45\.239\.7|10\.99\.0\.|10\.10\.1\.43|panel-api'; then
  static_fail "A10 healthcheck oracle" "healthcheck names a refused host"
else
  say_pass "A10 healthcheck has no GlassHosting host"
fi
if printf '%s\n' "$hc" | grep -q '127.0.0.1'; then
  say_pass "A10 healthcheck is local"
else
  static_fail "A10 healthcheck local" "127.0.0.1 missing"
fi
if grep -nE '(^|[^[:alnum:]_-])curl[[:space:]]+-' "${INSTALL}" | grep -E -v '127\.0\.0\.1|WINGS_URL'; then
  static_fail "A10 curl targets" "unexpected curl"
else
  say_pass "A10 curl is local healthcheck or the pinned wings URL"
fi

if grep -q -F 'Glasshouse Holding Group' "${FREE}/brand/banner.txt" \
  && grep -q -F 'GlassHosting' "${FREE}/brand/banner.txt" \
  && grep -q -F 'GlassGamePanel' "${FREE}/brand/banner.txt" \
  && grep -q -F 'glassgamepanel-wings-free-v0.1.0' "${FREE}/brand/banner.txt" \
  && grep -q -F '# GlassGamePanel free · Wings one-click' "${FREE}/README.md" \
  && grep -q -F 'GlassGamePanel free Wings installer finished' "${INSTALL}" \
  && grep -q -F 'GlassGamePanel Wings (Glasshouse Holding Group / GlassHosting)' "${FREE}/systemd/wings.service.template"; then
  say_pass "A11 brand surfaces and artifact prefix"
else
  static_fail "A11 brand" "a required brand string is missing"
fi

docs_ok=1
for docs_file in "${FREE}/README.md" "${FREE}/ATTRIBUTION.md" "${FREE}/brand/banner.txt"; do
  if grep -q -F 'PUBLISH HOLD' "$docs_file" \
    || grep -q -F 'Founder YES' "$docs_file" \
    || grep -q -F 'SecNOA' "$docs_file" \
    || grep -q -i -E 'soft[-_ ]launch|hard deny|estate' "$docs_file" \
    || grep -q -F 'panel-api-test' "$docs_file" \
    || grep -q -E 'CT316|CT312' "$docs_file"; then
    static_fail "A12 consumer docs" "ops vocabulary in ${docs_file}"
    docs_ok=0
  fi
done
if grep -n -i -E 'soft[-_ ]launch|hard deny|estate|phase c|publish hold' "${INSTALL}" \
  | grep -v -E 'include_soft_launch|include-soft-launch|soft\[-_\]launch|softlaunch|soft\[\[:space:\]\]'; then
  static_fail "A12 installer wording" "operator-facing installer text still uses internal wording"
  docs_ok=0
fi
if [[ "$docs_ok" -eq 1 ]] \
  && grep -q -F 'sha256sum -c SHA256SUMS' "${FREE}/README.md" \
  && grep -q -F 'operator-owned' "${FREE}/README.md" \
  && grep -q -F 'sales@glasshosting.com' "${FREE}/README.md" \
  && grep -q -F 'free-ggp' "${FREE}/README.md" \
  && grep -q -F 'WHMCS' "${FREE}/README.md" \
  && grep -q -F 'DIY' "${FREE}/README.md" \
  && grep -q -F 'Verify SHA256SUMS' "${FREE}/brand/banner.txt" \
  && grep -q -F 'Verify `SHA256SUMS`' "${FREE}/ATTRIBUTION.md" \
  && [[ -f "${FREE}/SHA256SUMS" ]]; then
  say_pass "A12 docs use consumer language and require checksum verify"
else
  [[ "$docs_ok" -eq 1 ]] && static_fail "A12 checksum docs" "README, attribution, banner, or SHA256SUMS incomplete"
fi

if grep -R -n -E --exclude 'refuse_unowned_servers.sh' 'd0c77bd4-0a24-4b2d-8e73-213f2b37dce4|38\.135\.179\.34|fdba:17c8:6c94' "${FREE}"; then
  static_fail "D5 private test targets" "packaging tree names a private test target"
else
  say_pass "D5 packaging has no private test-target hints"
fi

uuid_embed=0
for u in "${UUIDS[@]}"; do
  if grep -R -F -q "$u" "${FREE}" --exclude 'refused-servers.json' --exclude 'README.md' --exclude 'SHA256SUMS'; then
    static_fail "uuid embedded outside fragment and README" "$u"
    uuid_embed=1
  fi
done
if [[ "$uuid_embed" -eq 0 ]]; then
  say_pass "deny uuids stay in the fragment and the refuse docs"
fi

echo "== SHA256SUMS =="
if (cd "${FREE}" && sha256sum -c SHA256SUMS); then
  say_pass "SHA256SUMS verifies packaging tree"
else
  static_fail "SHA256SUMS" "checksum mismatch"
fi

HOST_AFTER="$(snapshot_host)"
if [[ "$HOST_BEFORE" == "$HOST_AFTER" ]]; then
  say_pass "host wings paths unchanged"
else
  static_fail "host mutated" "before=${HOST_BEFORE} after=${HOST_AFTER}"
fi

echo
echo "passes=${passes} failures=${failures}"
if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
exit 0
