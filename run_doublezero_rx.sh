#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEV="${DEV:-enp1s0f0}"
QUEUE="${QUEUE:-3}"
CPU="${CPU:-3}"
ATTACH_MODE="${ATTACH_MODE:-drv}"
BPF_OBJECT="${BPF_OBJECT:-${DOUBLEZERO_XDP_BPF_OBJECT:-$ROOT_DIR/../doublezero-xdp/target/bpfel-unknown-none/release/doublezero-xdp-ebpf}}"
BIN="${BIN:-$ROOT_DIR/target/debug/doublezero_rx}"
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
}

trap 'cleanup; exit 130' INT TERM
trap cleanup EXIT

rm -f "${LOG}"
truncate -s 0 "${LOG}"

RUST_LOG="${RUST_LOG_VALUE}" RX_PATH_BENCH="${RX_PATH_BENCH_VALUE}" "${BIN}" \
    --iface "${DEV}" \
    --queue "${QUEUE}" \
    --cpu "${CPU}" \
    --attach-mode "${ATTACH_MODE}" \
    --bpf-object "${BPF_OBJECT}" \
    --packet-log-limit "${PACKET_LOG_LIMIT}" \
    >"${LOG}" 2>&1 &

PID="$!"
echo "${PID}" > "${PID_FILE}"

deadline=$((SECONDS + WAIT_TIMEOUT_SECS))
while (( SECONDS < deadline )); do
    if ! kill -0 "${PID}" 2>/dev/null; then
        echo "doublezero_rx exited before XDP RX armed; see ${LOG}" >&2
        cat "${LOG}" >&2 || true
        exit 1
    fi

    if grep -q "XDP RX armed" "${LOG}" 2>/dev/null; then
        break
    fi

    sleep 1
done

if ! grep -q "XDP RX armed" "${LOG}" 2>/dev/null; then
    echo "timed out waiting for XDP RX armed; see ${LOG}" >&2
    exit 1
fi

ethtool -U "${DEV}" delete "${FDIR_LOC}" >/dev/null 2>&1 || true
ethtool -U "${DEV}" flow-type ip4 \
    src-ip "${FDIR_SRC_IP}" \
    dst-ip "${FDIR_DST_IP}" \
    action "${FDIR_ACTION_QUEUE}" \
    loc "${FDIR_LOC}"

echo "doublezero_rx running with pid ${PID}"
echo "log: ${LOG}"
echo "fdir: ${DEV} src=${FDIR_SRC_IP} dst=${FDIR_DST_IP} -> queue ${FDIR_ACTION_QUEUE} loc ${FDIR_LOC}"

wait "${PID}"
