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
FDIR_SRC_IP="${FDIR_SRC_IP:-<your-src-ip>}"
FDIR_DST_IP="${FDIR_DST_IP:-<your-dst-ip>}"
FDIR_ACTION_QUEUE="${FDIR_ACTION_QUEUE:-3}"

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

ethtool -U "${DEV}" delete "${FDIR_LOC}" >/dev/null 2>&1 || true
ethtool -U "${DEV}" flow-type ip4 \
    src-ip "${FDIR_SRC_IP}" \
    dst-ip "${FDIR_DST_IP}" \
    action "${FDIR_ACTION_QUEUE}" \
    loc "${FDIR_LOC}"
FDIR_INSTALLED=1

echo "doublezero_xdp_rx running with pid ${PID}"
echo "log: ${LOG}"
if [[ "$SHOW_STARTUP_LOGS" != "0" ]]; then
    echo "fdir: ${DEV} src=${FDIR_SRC_IP} dst=${LOCAL_IP_LABEL} -> queue ${FDIR_ACTION_QUEUE} loc ${FDIR_LOC}"
else
    echo "fdir: ${DEV} src=${FDIR_SRC_IP} dst=${FDIR_DST_IP} -> queue ${FDIR_ACTION_QUEUE} loc ${FDIR_LOC}"
fi

start_xdpdump_demo_capture

wait "${PID}"
