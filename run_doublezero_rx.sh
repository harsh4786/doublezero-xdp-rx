#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEV="${DEV:-enp1s0f0}"
QUEUE="${QUEUE:-3}"
CPU="${CPU:-3}"
ATTACH_MODE="${ATTACH_MODE:-drv}"
ZERO_COPY="${ZERO_COPY:-true}"
BPF_OBJECT="${BPF_OBJECT:-${DOUBLEZERO_XDP_BPF_OBJECT:-$ROOT_DIR/target/bpfel-unknown-none/release/doublezero-xdp-ebpf}}"
BIN="${BIN:-$ROOT_DIR/target/release/doublezero_xdp_rx}"
LOG="${LOG:-/tmp/doublezero-rx.log}"
PID_FILE="${PID_FILE:-/tmp/doublezero-rx.pid}"

FDIR_LOC="${FDIR_LOC:-2043}"
# "auto" reads the outer GRE endpoints from TUNNEL_IFACE and reinstalls the rule if the seat moves
# to another Doublezero device. Set explicit IPs to pin a static rule instead.
FDIR_SRC_IP="${FDIR_SRC_IP:-auto}"
FDIR_DST_IP="${FDIR_DST_IP:-auto}"
FDIR_ACTION_QUEUE="${FDIR_ACTION_QUEUE:-3}"
FDIR_WATCH_SECS="${FDIR_WATCH_SECS:-2}"
TUNNEL_IFACE="${TUNNEL_IFACE:-doublezero1}"

WAIT_TIMEOUT_SECS="${WAIT_TIMEOUT_SECS:-20}"
RUST_LOG_VALUE="${RUST_LOG:-warn,agave_xdp_rx::rx_loop=info}"
RX_PATH_BENCH_VALUE="${RX_PATH_BENCH:-0}"
PACKET_LOG_LIMIT="${PACKET_LOG_LIMIT:-1000000000}"
SHOW_STARTUP_LOGS="${SHOW_STARTUP_LOGS:-0}"
CLEAR_STARTUP_SCREEN="${CLEAR_STARTUP_SCREEN:-$SHOW_STARTUP_LOGS}"
SHOW_STARTUP_POLL_SECS="${SHOW_STARTUP_POLL_SECS:-1}"
SHOW_XDPDUMP_LOGS="${SHOW_XDPDUMP_LOGS:-0}"
XDPDUMP_DELAY_SECS="${XDPDUMP_DELAY_SECS:-3}"
XDPDUMP_DURATION_SECS="${XDPDUMP_DURATION_SECS:-}"
XDPDUMP_RX_CAPTURE="${XDPDUMP_RX_CAPTURE:-exit}"
XDPDUMP_PROGRAMS="${XDPDUMP_PROGRAMS:-doublezero_xdp_redirect}"
LOCAL_IP_LABEL="${LOCAL_IP_LABEL:-LOCAL_IP}"
ATTACH_RETRY_ON_DRV_BUSY="${ATTACH_RETRY_ON_DRV_BUSY:-0}"
WAIT_DOUBLEZERO_READY="${WAIT_DOUBLEZERO_READY:-1}"
DOUBLEZERO_WAIT_TIMEOUT_SECS="${DOUBLEZERO_WAIT_TIMEOUT_SECS:-60}"
FDIR_INSTALLED=0
FDIR_AUTO=0
if [[ "${FDIR_SRC_IP}" == "auto" || "${FDIR_DST_IP}" == "auto" ]]; then
    FDIR_AUTO=1
fi

cleanup() {
    local pid=""
    if [[ -f "${PID_FILE}" ]]; then
        pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
    fi

    if [[ -n "${pid}" ]]; then
        kill "${pid}" 2>/dev/null || true
        sleep 1
        if kill -0 "${pid}" 2>/dev/null; then
            kill -9 "${pid}" 2>/dev/null || true
        fi
    fi

    rm -f "${PID_FILE}"

    if [[ -n "${XDPDUMP_BG_PID:-}" ]]; then
        kill "${XDPDUMP_BG_PID}" 2>/dev/null || true
        wait "${XDPDUMP_BG_PID}" 2>/dev/null || true
    fi

    if [[ -n "${FDIR_WATCH_PID:-}" ]]; then
        kill "${FDIR_WATCH_PID}" 2>/dev/null || true
        wait "${FDIR_WATCH_PID}" 2>/dev/null || true
    fi

    if [[ "${FDIR_INSTALLED:-0}" == "1" ]]; then
        ethtool -U "${DEV}" delete "${FDIR_LOC}" >/dev/null 2>&1 || true
    fi
}

emit_startup_snapshot() {
    local label="$1"
    if [[ "$SHOW_STARTUP_LOGS" == "0" ]]; then
        return
    fi

    echo
    echo "[startup] ${label}"
    echo "[startup] multicast routes"
    ip route show 2>/dev/null | grep '^233\.84\.178\.' || true
}

clear_startup_screen() {
    if [[ "$CLEAR_STARTUP_SCREEN" == "0" || ! -t 1 ]]; then
        return
    fi

    if command -v clear >/dev/null 2>&1; then
        clear
    else
        printf '\033c'
    fi
}

emit_tunnel_status_change() {
    local status_output="$1"
    local state=""

    if grep -q 'BGP Session Up' <<<"$status_output"; then
        state="BGP Session Up"
    elif grep -q 'disconnected' <<<"$status_output"; then
        state="disconnected"
    else
        state="transitioning"
    fi

    if [[ "${LAST_TUNNEL_STATE:-}" == "BGP Session Up" && "$state" == "transitioning" ]]; then
        return
    fi

    if [[ "${LAST_TUNNEL_STATE:-}" != "$state" ]]; then
        echo "[startup] tunnel status: ${state}"
        LAST_TUNNEL_STATE="$state"
    fi
}

doublezero_multicast_routes_ready() {
    ip route show 2>/dev/null | grep -q '^233\.84\.178\.'
}

wait_for_doublezero_ready() {
    if [[ "$WAIT_DOUBLEZERO_READY" == "0" ]]; then
        return
    fi

    local deadline=$((SECONDS + DOUBLEZERO_WAIT_TIMEOUT_SECS))
    local status_output=""
    while (( SECONDS < deadline )); do
        if command -v doublezero >/dev/null 2>&1; then
            status_output="$(doublezero status 2>/dev/null || true)"
            if [[ "$SHOW_STARTUP_LOGS" != "0" ]]; then
                emit_tunnel_status_change "$status_output"
            fi
            if doublezero_multicast_routes_ready; then
                if [[ "$SHOW_STARTUP_LOGS" != "0" ]] && ! grep -q 'BGP Session Up' <<<"$status_output"; then
                    echo "[startup] multicast routes ready; starting XDP RX while tunnel status settles"
                fi
                return
            fi
        fi
        sleep "${SHOW_STARTUP_POLL_SECS}"
    done

    echo "timed out waiting for Doublezero multicast routes" >&2
    if command -v doublezero >/dev/null 2>&1; then
        doublezero status >&2 || true
    fi
    ip route show >&2 || true
    exit 1
}

# Prints "<remote> <local>" for the GRE tunnel, i.e. the outer src/dst of Doublezero traffic.
# Prints nothing (and succeeds) while the tunnel is down, so set -e does not end the watcher.
tunnel_endpoints() {
    ip -d -o link show dev "${TUNNEL_IFACE}" 2>/dev/null |
        awk '{ for (i = 1; i < NF; i++) if ($i == "link/gre" && $(i + 2) == "peer") { print $(i + 3), $(i + 1); exit } }' ||
        true
}

resolve_fdir_endpoints() {
    if [[ "$FDIR_AUTO" == "0" ]]; then
        return
    fi

    local endpoints
    endpoints="$(tunnel_endpoints)"
    if [[ -z "$endpoints" ]]; then
        echo "cannot read GRE endpoints from ${TUNNEL_IFACE}; set FDIR_SRC_IP and FDIR_DST_IP" >&2
        exit 1
    fi
    read -r FDIR_SRC_IP FDIR_DST_IP <<<"$endpoints"
}

install_fdir_rule() {
    ethtool -U "${DEV}" delete "${FDIR_LOC}" >/dev/null 2>&1 || true
    ethtool -U "${DEV}" flow-type ip4 \
        src-ip "${FDIR_SRC_IP}" \
        dst-ip "${FDIR_DST_IP}" \
        action "${FDIR_ACTION_QUEUE}" \
        loc "${FDIR_LOC}"
}

# Every online CPU except the RX core, so the watcher never preempts the busy-poll loop.
cpus_except_rx_core() {
    local online range lo hi cpu out=""
    online="$(cat /sys/devices/system/cpu/online 2>/dev/null)" || return
    for range in ${online//,/ }; do
        lo="${range%-*}"
        hi="${range#*-}"
        for ((cpu = lo; cpu <= hi; cpu++)); do
            if [[ "$cpu" != "$CPU" ]]; then
                out+="${out:+,}${cpu}"
            fi
        done
    done
    echo "$out"
}

# A Doublezero seat can move to another device (dynamic seat allocation, reprovisioning), which
# changes the outer GRE endpoints. A stale rule steers the feed away from the AF_XDP queue.
watch_tunnel_endpoints() {
    local endpoints src dst
    while kill -0 "${PID}" 2>/dev/null; do
        sleep "${FDIR_WATCH_SECS}"
        endpoints="$(tunnel_endpoints)"
        if [[ -z "$endpoints" ]]; then
            continue
        fi
        read -r src dst <<<"$endpoints"
        if [[ "$src" == "$FDIR_SRC_IP" && "$dst" == "$FDIR_DST_IP" ]]; then
            continue
        fi
        echo "[fdir] ${TUNNEL_IFACE} endpoints changed: src ${FDIR_SRC_IP} -> ${src}; reinstalling rule loc ${FDIR_LOC}"
        FDIR_SRC_IP="$src"
        FDIR_DST_IP="$dst"
        install_fdir_rule || echo "[fdir] failed to reinstall rule on ${DEV}" >&2
    done
}

start_fdir_watch() {
    if [[ "$FDIR_AUTO" == "0" || "$FDIR_WATCH_SECS" == "0" ]]; then
        return
    fi

    local cpus=""
    if command -v taskset >/dev/null 2>&1; then
        cpus="$(cpus_except_rx_core)"
    fi
    if [[ -n "$cpus" ]]; then
        watch_tunnel_endpoints &
        FDIR_WATCH_PID="$!"
        taskset -a -p -c "$cpus" "${FDIR_WATCH_PID}" >/dev/null 2>&1 || true
    else
        watch_tunnel_endpoints &
        FDIR_WATCH_PID="$!"
    fi
}

start_receiver() {
    local attach_mode="$1"
    local zero_copy="$2"

    RUST_LOG="${RUST_LOG_VALUE}" RX_PATH_BENCH="${RX_PATH_BENCH_VALUE}" "${BIN}" \
        --iface "${DEV}" \
        --queue "${QUEUE}" \
        --cpu "${CPU}" \
        --attach-mode "${attach_mode}" \
        --zero-copy "${zero_copy}" \
        --bpf-object "${BPF_OBJECT}" \
        --packet-log-limit "${PACKET_LOG_LIMIT}" \
        >"${LOG}" 2>&1 &

    PID="$!"
    echo "${PID}" > "${PID_FILE}"
}

start_xdpdump_demo_capture() {
    if [[ "$SHOW_XDPDUMP_LOGS" == "0" ]]; then
        return
    fi
    if ! command -v xdpdump >/dev/null 2>&1; then
        echo "[startup][xdpdump] xdpdump not found; skipping capture"
        return
    fi

    (
        sleep "${XDPDUMP_DELAY_SECS}"
        if ! kill -0 "${PID}" 2>/dev/null; then
            exit 0
        fi
        echo "[startup][xdpdump] starting xdpdump -i ${DEV} --rx-capture=${XDPDUMP_RX_CAPTURE} -p ${XDPDUMP_PROGRAMS} after ${XDPDUMP_DELAY_SECS}s"
        if [[ -n "${XDPDUMP_DURATION_SECS}" && "${XDPDUMP_DURATION_SECS}" != "0" ]]; then
            timeout "${XDPDUMP_DURATION_SECS}" \
                xdpdump -i "${DEV}" \
                    --rx-capture="${XDPDUMP_RX_CAPTURE}" \
                    -p "${XDPDUMP_PROGRAMS}" 2>&1 || true
        else
            xdpdump -i "${DEV}" \
                --rx-capture="${XDPDUMP_RX_CAPTURE}" \
                -p "${XDPDUMP_PROGRAMS}" 2>&1 || true
        fi
    ) &
    XDPDUMP_BG_PID="$!"
}

trap 'cleanup; exit 130' INT TERM
trap cleanup EXIT

cleanup
clear_startup_screen
rm -f "${LOG}"
truncate -s 0 "${LOG}"
emit_startup_snapshot "pre-launch"
wait_for_doublezero_ready
start_receiver "${ATTACH_MODE}" "${ZERO_COPY}"

deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
while (( SECONDS < deadline )); do
    if [[ "$SHOW_STARTUP_LOGS" != "0" ]] && command -v doublezero >/dev/null 2>&1; then
        emit_tunnel_status_change "$(doublezero status 2>/dev/null || true)"
    fi

    if ! kill -0 "${PID}" 2>/dev/null; then
        if [[ "${ATTACH_MODE}" == "drv" && "${ATTACH_RETRY_ON_DRV_BUSY}" == "1" ]] && \
            grep -q 'bpf_link_create.*ResourceBusy' "${LOG}" 2>/dev/null; then
            # Generic (skb) XDP cannot bind AF_XDP in zero-copy mode.
            echo "[startup] drv attach busy; retrying with skb (copy mode)"
            rm -f "${LOG}"
            truncate -s 0 "${LOG}"
            start_receiver "skb" "false"
            ATTACH_MODE="skb"
            ZERO_COPY="false"
            deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
            continue
        fi
        echo "doublezero_xdp_rx exited before XDP RX armed; see ${LOG}" >&2
        cat "${LOG}" >&2 || true
        exit 1
    fi

    if grep -q "XDP RX armed" "${LOG}" 2>/dev/null; then
        break
    fi

    sleep "${SHOW_STARTUP_POLL_SECS}"
done

if ! grep -q "XDP RX armed" "${LOG}" 2>/dev/null; then
    echo "timed out waiting for XDP RX armed; see ${LOG}" >&2
    exit 1
fi

emit_startup_snapshot "xdp rx armed"

resolve_fdir_endpoints
install_fdir_rule
FDIR_INSTALLED=1

echo "doublezero_xdp_rx running with pid ${PID}"
echo "log: ${LOG}"
if [[ "$SHOW_STARTUP_LOGS" != "0" ]]; then
    echo "fdir: ${DEV} src=${FDIR_SRC_IP} dst=${LOCAL_IP_LABEL} -> queue ${FDIR_ACTION_QUEUE} loc ${FDIR_LOC}"
else
    echo "fdir: ${DEV} src=${FDIR_SRC_IP} dst=${FDIR_DST_IP} -> queue ${FDIR_ACTION_QUEUE} loc ${FDIR_LOC}"
fi

start_fdir_watch
start_xdpdump_demo_capture

wait "${PID}"
