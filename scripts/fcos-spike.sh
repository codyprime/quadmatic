#!/usr/bin/env bash
# Milestone 0 Fedora CoreOS spike verification script for quadmatic.
# Validates:
#   1. L3Mdev sysctls, VLAN + VRF + macvlan + rootless pasta isolation (inbound/outbound & sshd isolation)
#   2. Rootless systemd user unit cgroupv2 paths for podman pull, conmon, and pasta
#   3. Rootless user provisioning under /var/home/qmspike, linger, DBus wait, daemon-reload, and secret piping
set -euo pipefail

SPIKE_USER="${SPIKE_USER:-qmspike}"
SPIKE_HOME="/var/home/${SPIKE_USER}"
VLAN_IFACE="${VLAN_IFACE:-qm-vlan99}"
VLAN_ID="${VLAN_ID:-99}"
VRF_IFACE="${VRF_IFACE:-qmv-2999}"
VRF_TABLE="${VRF_TABLE:-12999}"
MACVLAN_IFACE="${MACVLAN_IFACE:-qm-2999}"
MACVLAN_MAC="${MACVLAN_MAC:-02:71:6d:00:29:99}"
TRUNK_IFACE="${TRUNK_IFACE:-}"
TEST_IMAGE="${TEST_IMAGE:-docker.io/library/busybox:latest}"
OUTBOUND_TEST_URL="${OUTBOUND_TEST_URL:-http://1.1.1.1}"
CONTAINER_NAME="qmspike-pasta-test"
SECRET_NAME="spike_sec"

CREATED_USER=0
CREATED_VLAN=0
CREATED_VRF=0
CREATED_MACVLAN=0
SPIKE_UID=""

log() {
  printf '[fcos-spike] %s\n' "$*"
}

fail() {
  printf '[fcos-spike] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" >/dev/null 2>&1 || fail "missing required command: $cmd"
  done
}

cleanup() {
  set +e
  log "Cleaning up spike resources..."
  if [[ -n "$SPIKE_UID" ]] && id "$SPIKE_USER" >/dev/null 2>&1; then
    systemd-run --machine="${SPIKE_USER}@.host" --user --wait --quiet \
      podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    systemd-run --machine="${SPIKE_USER}@.host" --user --wait --quiet \
      podman secret rm "$SECRET_NAME" >/dev/null 2>&1 || true
    systemctl --user -M "${SPIKE_USER}@" stop qmspike-pull-probe.service >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_MACVLAN" -eq 1 ]]; then
    nmcli connection down "$MACVLAN_IFACE" >/dev/null 2>&1 || true
    nmcli connection delete "$MACVLAN_IFACE" >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_VRF" -eq 1 ]]; then
    ip route del table "$VRF_TABLE" unreachable default metric 8192 >/dev/null 2>&1 || true
    nmcli connection down "$VRF_IFACE" >/dev/null 2>&1 || true
    nmcli connection delete "$VRF_IFACE" >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_VLAN" -eq 1 ]]; then
    nmcli connection down "$VLAN_IFACE" >/dev/null 2>&1 || true
    nmcli connection delete "$VLAN_IFACE" >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_USER" -eq 1 ]] && id "$SPIKE_USER" >/dev/null 2>&1; then
    loginctl disable-linger "$SPIKE_USER" >/dev/null 2>&1 || true
    loginctl terminate-user "$SPIKE_USER" >/dev/null 2>&1 || true
    userdel -r "$SPIKE_USER" >/dev/null 2>&1 || true
    rm -rf "$SPIKE_HOME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

detect_trunk_iface() {
  if [[ -n "$TRUNK_IFACE" ]]; then
    return
  fi
  TRUNK_IFACE="$(ip -o route show default | awk '{print $5; exit}')"
  [[ -n "$TRUNK_IFACE" ]] || fail "could not detect default trunk interface; set TRUNK_IFACE"
}

check_3_provision_user() {
  log "=== Check 3 (part 1): Create user ${SPIKE_USER} under ${SPIKE_HOME}, enable linger, wait for bus, daemon-reload ==="
  if id "$SPIKE_USER" >/dev/null 2>&1; then
    fail "test user ${SPIKE_USER} already exists; remove it before running spike"
  fi

  mkdir -p /var/home
  useradd -m -d "$SPIKE_HOME" -s /sbin/nologin "$SPIKE_USER"
  CREATED_USER=1
  SPIKE_UID="$(id -u "$SPIKE_USER")"
  log "Created ${SPIKE_USER} (uid=${SPIKE_UID}, home=${SPIKE_HOME})"

  loginctl enable-linger "$SPIKE_USER"
  local bus_path="/run/user/${SPIKE_UID}/bus"
  local waited=0
  while [[ ! -S "$bus_path" ]]; do
    if [[ "$waited" -ge 30 ]]; then
      fail "timed out waiting for ${bus_path}"
    fi
    sleep 1
    waited=$((waited + 1))
  done
  log "Detected user bus socket at ${bus_path}"

  systemctl --user -M "${SPIKE_USER}@" daemon-reload
  log "systemctl --user -M ${SPIKE_USER}@ daemon-reload succeeded"
}

assert_tcp_blocked() {
  local target_ip="$1"
  local target_port="$2"
  local label="$3"
  local out rc=0
  out="$(systemd-run --machine="${SPIKE_USER}@.host" --user --wait --quiet --pipe \
    podman exec "$CONTAINER_NAME" sh -c 'nc -w 2 "$1" "$2" </dev/null 2>&1' _ "$target_ip" "$target_port")" || rc=$?
  if [[ "$rc" -eq 0 ]] || [[ "$out" == *"SSH-"* ]]; then
    fail "container unexpectedly reached ${target_ip}:${target_port} (${label}): ${out}"
  fi
  if [[ "$rc" -eq 127 ]] || [[ "$out" == *"Usage:"* ]] || [[ "$out" == *"unrecognized option"* ]] || [[ "$out" == *"invalid option"* ]] || [[ "$out" == *"not found"* ]]; then
    fail "isolation probe command failed for ${target_ip}:${target_port} (rc=${rc}): ${out}"
  fi
}

check_1_networking_and_pasta() {
  log "=== Check 1: L3Mdev sysctls, VLAN/VRF/macvlan setup, and rootless pasta isolation ==="
  local tcp_l3mdev udp_l3mdev
  tcp_l3mdev="$(sysctl -n net.ipv4.tcp_l3mdev_accept)"
  udp_l3mdev="$(sysctl -n net.ipv4.udp_l3mdev_accept)"
  log "net.ipv4.tcp_l3mdev_accept=${tcp_l3mdev}, net.ipv4.udp_l3mdev_accept=${udp_l3mdev}"
  [[ "$tcp_l3mdev" == "0" ]] || fail "expected net.ipv4.tcp_l3mdev_accept == 0, got ${tcp_l3mdev}"
  [[ "$udp_l3mdev" == "0" ]] || fail "expected net.ipv4.udp_l3mdev_accept == 0, got ${udp_l3mdev}"

  detect_trunk_iface
  log "Using trunk interface: ${TRUNK_IFACE}"

  if ip link show "$VLAN_IFACE" >/dev/null 2>&1; then
    log "Reusing existing VLAN interface ${VLAN_IFACE}"
  else
    nmcli connection add type vlan con-name "$VLAN_IFACE" ifname "$VLAN_IFACE" \
      dev "$TRUNK_IFACE" id "$VLAN_ID" ipv4.method disabled ipv6.method disabled
    CREATED_VLAN=1
    nmcli connection up "$VLAN_IFACE"
  fi

  nmcli connection add type vrf con-name "$VRF_IFACE" ifname "$VRF_IFACE" \
    table "$VRF_TABLE" ipv4.method disabled ipv6.method disabled
  CREATED_VRF=1
  nmcli connection up "$VRF_IFACE"
  ip route replace table "$VRF_TABLE" unreachable default metric 8192
  ip route show table "$VRF_TABLE"

  nmcli connection add type macvlan con-name "$MACVLAN_IFACE" ifname "$MACVLAN_IFACE" \
    dev "$VLAN_IFACE" mode private master "$VRF_IFACE" \
    ethernet.cloned-mac-address "$MACVLAN_MAC" \
    ipv4.method auto ipv4.ignore-auto-dns yes ipv6.method disabled
  CREATED_MACVLAN=1
  nmcli connection up "$MACVLAN_IFACE"

  local macvlan_ip=""
  local waited=0
  while [[ -z "$macvlan_ip" ]]; do
    macvlan_ip="$(ip -4 -o addr show dev "$MACVLAN_IFACE" scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    if [[ -n "$macvlan_ip" ]]; then
      break
    fi
    if [[ "$waited" -ge 30 ]]; then
      fail "timed out waiting for DHCP IPv4 address on ${MACVLAN_IFACE}"
    fi
    sleep 1
    waited=$((waited + 1))
  done
  log "Acquired DHCP IPv4 on ${MACVLAN_IFACE}: ${macvlan_ip}"

  # Ensure image is present before running pasta network test.
  systemd-run --machine="${SPIKE_USER}@.host" --user --wait --quiet \
    podman pull "$TEST_IMAGE"

  local pasta_net="pasta:--no-map-gw,--map-host-loopback,none,--ipv4-only,-i,${MACVLAN_IFACE},--outbound-if4,${MACVLAN_IFACE},-t,%${MACVLAN_IFACE}/8080:8080"
  log "Starting rootless container with network=${pasta_net}"
  systemd-run --machine="${SPIKE_USER}@.host" --user --wait --quiet \
    podman run -d --name "$CONTAINER_NAME" --network="$pasta_net" "$TEST_IMAGE" \
    sh -c 'mkdir -p /tmp/www && echo ok > /tmp/www/index.html && exec httpd -f -p 8080 -h /tmp/www'

  sleep 2
  log "Verifying inbound connectivity to ${macvlan_ip}:8080..."
  local body
  body="$(curl -fsS --max-time 5 "http://${macvlan_ip}:8080/index.html")"
  [[ "$body" == "ok" ]] || fail "unexpected inbound response from container: ${body}"
  log "Inbound check passed (received '${body}')"

  log "Verifying outbound connectivity from container..."
  systemd-run --machine="${SPIKE_USER}@.host" --user --wait --quiet \
    podman exec "$CONTAINER_NAME" wget -qO- --timeout=5 "$OUTBOUND_TEST_URL" >/dev/null
  log "Outbound check passed"

  log "Verifying isolation from host sshd (port 22 on host loopback and host primary IP)..."
  local host_ip
  host_ip="$(ip -4 -o addr show dev "$TRUNK_IFACE" scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)"
  assert_tcp_blocked 127.0.0.1 22 "host loopback isolation broken"
  if [[ -n "$host_ip" ]]; then
    assert_tcp_blocked "$host_ip" 22 "host primary IP sshd"
  fi
  log "Isolation from host sshd verified"
}

check_2_cgroup_paths() {
  log "=== Check 2: Inspect /proc/<pid>/cgroup for podman pull, conmon, and pasta inside rootless user unit ==="
  systemd-run --machine="${SPIKE_USER}@.host" --user --unit=qmspike-pull-probe --pipe --wait --quiet \
    sh -c 'podman pull --policy=always "$1" >/dev/null & p=$!; echo "--- podman pull (/proc/$p/cgroup) ---"; cat "/proc/$p/cgroup" 2>/dev/null || cat /proc/self/cgroup; wait "$p"' _ "$TEST_IMAGE"

  local conmon_pid pasta_pid
  conmon_pid="$(pgrep -u "$SPIKE_UID" -n conmon || true)"
  pasta_pid="$(pgrep -u "$SPIKE_UID" -n pasta || true)"

  [[ -n "$conmon_pid" ]] || fail "could not find conmon PID for uid ${SPIKE_UID}"
  [[ -n "$pasta_pid" ]] || fail "could not find pasta PID for uid ${SPIKE_UID}"

  log "--- conmon (pid=${conmon_pid}) /proc/${conmon_pid}/cgroup ---"
  cat "/proc/${conmon_pid}/cgroup"
  log "--- pasta (pid=${pasta_pid}) /proc/${pasta_pid}/cgroup ---"
  cat "/proc/${pasta_pid}/cgroup"
}

check_3_secret_pipe() {
  log "=== Check 3 (part 2): Pipe test secret via systemd-run into podman secret ==="
  printf 'spike-secret-value' | systemd-run --machine="${SPIKE_USER}@.host" --user --pipe --wait --quiet \
    podman secret create --replace "$SECRET_NAME" -

  local listed
  listed="$(systemd-run --machine="${SPIKE_USER}@.host" --user --pipe --wait --quiet \
    podman secret ls --format '{{.Name}}')"
  printf '%s\n' "$listed" | grep -qx "$SECRET_NAME" || fail "secret ${SECRET_NAME} not found after creation"
  log "Secret ${SECRET_NAME} created and verified via systemd-run --pipe"
}

main() {
  [[ "$EUID" -eq 0 ]] || fail "must run as root on a Fedora CoreOS test VM"
  require_cmd sysctl nmcli ip podman loginctl systemctl systemd-run useradd userdel curl pgrep awk grep

  check_3_provision_user
  check_1_networking_and_pasta
  check_2_cgroup_paths
  check_3_secret_pipe

  log "All Milestone 0 FCOS spike checks passed."
}

main "$@"
