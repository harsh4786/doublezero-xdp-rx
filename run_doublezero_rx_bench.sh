#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BENCH_DURATION_SECS="${BENCH_DURATION_SECS:-30}"
BENCH_MODE="${BENCH_MODE:-auto}"
KERNEL_LOG="${KERNEL_LOG:-/tmp/doublezero-kernel-rx.log}"
XDP_LOG="${XDP_LOG:-/tmp/doublezero-rx.log}"

KERNEL_BIN="${KERNEL_BIN:-$ROOT_DIR/target/release/doublezero_kernel_rx}"
XDP_BIN="${XDP_BIN:-$ROOT_DIR/target/release/doublezero_xdp_rx}"
XDP_SCRIPT="${XDP_SCRIPT:-$ROOT_DIR/run_doublezero_rx.sh}"

KERNEL_IFACE="${KERNEL_IFACE:-doublezero1}"
KERNEL_GROUP="${KERNEL_GROUP:-233.84.178.12}"
KERNEL_PORT="${KERNEL_PORT:-7733}"
KERNEL_CPU="${KERNEL_CPU:-3}"
KERNEL_PACKET_LOG_LIMIT="${KERNEL_PACKET_LOG_LIMIT:-0}"
KERNEL_RECV_BUFFER_MB="${KERNEL_RECV_BUFFER_MB:-64}"
KERNEL_WAIT_READY_SECS="${KERNEL_WAIT_READY_SECS:-60}"

DEV="${DEV:-enp1s0f0}"
QUEUE="${QUEUE:-3}"
CPU="${CPU:-4}"
ATTACH_MODE="${ATTACH_MODE:-drv}"
XDP_PACKET_LOG_LIMIT="${XDP_PACKET_LOG_LIMIT:-0}"

case "$BENCH_MODE" in
    auto|both|kernel|xdp) ;;
    *)
        echo "[!] invalid BENCH_MODE=${BENCH_MODE}; expected auto, both, kernel, or xdp" >&2
        exit 2
        ;;
esac

RUN_KERNEL=0
RUN_XDP=0
case "$BENCH_MODE" in
    both)
        RUN_KERNEL=1
        RUN_XDP=1
        ;;
    kernel)
        RUN_KERNEL=1
        ;;
    xdp)
        RUN_XDP=1
        ;;
    auto)
        if [[ -e "/sys/class/net/${KERNEL_IFACE}" ]]; then
            RUN_KERNEL=1
        else
            echo "[*] Kernel interface ${KERNEL_IFACE} not found; auto mode will run XDP only."
        fi
        RUN_XDP=1
        ;;
esac

if (( RUN_KERNEL == 1 )) && [[ ! -e "/sys/class/net/${KERNEL_IFACE}" ]]; then
    echo "[!] Kernel interface ${KERNEL_IFACE} not found. Set KERNEL_IFACE=... or BENCH_MODE=xdp." >&2
    exit 1
fi

stop_pid_file() {
    local pid_file="$1"
    local pid=""
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -n "$pid" ]]; then
        kill "$pid" 2>/dev/null || true
        sleep 1
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pid_file" 2>/dev/null || true
}

wait_for_log_pattern() {
    local log="$1" pattern="$2" timeout_secs="$3" label="$4" pid="$5"
    local deadline=$((SECONDS + timeout_secs))
    while (( SECONDS < deadline )); do
        if [[ -f "$log" ]] && grep -q "$pattern" "$log" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[!] ${label} exited before readiness; see ${log}" >&2
            tail -20 "$log" 2>/dev/null || true
            return 1
        fi
        sleep 1
    done
    echo "[!] timed out waiting for ${label}; see ${log}" >&2
    tail -20 "$log" 2>/dev/null || true
    return 1
}

wait_for_kernel_path_ready() {
    local deadline=$((SECONDS + KERNEL_WAIT_READY_SECS))
    while (( SECONDS < deadline )); do
        if [[ ! -e "/sys/class/net/${KERNEL_IFACE}" ]]; then
            sleep 1
            continue
        fi

        if command -v doublezero >/dev/null 2>&1; then
            if doublezero status 2>/dev/null | grep -q 'BGP Session Up'; then
                return 0
            fi
        else
            return 0
        fi

        sleep 1
    done

    echo "[!] kernel path not ready after ${KERNEL_WAIT_READY_SECS}s; iface=${KERNEL_IFACE}" >&2
    if command -v doublezero >/dev/null 2>&1; then
        doublezero status >&2 || true
    fi
    return 1
}

summarize_final() {
    local label="$1" log="$2"
    local line=""
    if [[ "$label" == "xdp" ]]; then
        line="$(grep -E 'rx queue=' "$log" 2>/dev/null | awk '$0 !~ /pps=0( |$)/ { line=$0 } END { print line }' || true)"
    else
        line="$(grep -E '(kernel_rx_final|rx queue=)' "$log" 2>/dev/null | tail -1 || true)"
    fi
    if [[ -n "$line" ]]; then
        echo "${label}: ${line}"
    else
        echo "${label}: no summary found in ${log}"
    fi
}

field_value() {
    local line="$1" key="$2"
    awk -v key="$key" '{
        for (i = 1; i <= NF; i++) {
            split($i, kv, "=")
            if (kv[1] == key) {
                print kv[2]
                exit
            }
        }
    }' <<<"$line"
}

ns_to_us() {
    local ns="$1"
    if [[ -z "$ns" || "$ns" == "n/a" ]]; then
        echo "n/a"
    else
        awk -v ns="$ns" 'BEGIN { printf "%.2f", ns / 1000 }'
    fi
}

cpu_core_id() {
    local cpu="$1"
    cat "/sys/devices/system/cpu/cpu${cpu}/topology/core_id" 2>/dev/null || echo "n/a"
}

cpu_siblings() {
    local cpu="$1"
    cat "/sys/devices/system/cpu/cpu${cpu}/topology/thread_siblings_list" 2>/dev/null || echo "n/a"
}

print_table() {
    local kernel_line xdp_rx_line xdp_bench_line
    kernel_line="$(grep -E 'kernel_rx_final' "$KERNEL_LOG" 2>/dev/null | tail -1 || true)"
    xdp_rx_line="$(grep -E 'rx queue=' "$XDP_LOG" 2>/dev/null | awk '$0 !~ /pps=0( |$)/ { line=$0 } END { print line }' || true)"
    xdp_bench_line="$(grep -E 'RX_PATH_BENCH:' "$XDP_LOG" 2>/dev/null | tail -1 || true)"

    local kernel_packets kernel_p50 kernel_p90 kernel_p95 kernel_p99 kernel_avg
    local xdp_packets xdp_p50 xdp_p90 xdp_p95 xdp_p99 xdp_avg

    kernel_packets="$(field_value "$kernel_line" packets)"
    kernel_p50="$(field_value "$kernel_line" kernel_to_user_p50_ns)"
    kernel_p90="$(field_value "$kernel_line" kernel_to_user_p90_ns)"
    kernel_p95="$(field_value "$kernel_line" kernel_to_user_p95_ns)"
    kernel_p99="$(field_value "$kernel_line" kernel_to_user_p99_ns)"
    kernel_avg="$(field_value "$kernel_line" kernel_to_user_avg_ns)"

    xdp_packets="$(field_value "$xdp_rx_line" total_packets)"
    xdp_p50="$(field_value "$xdp_bench_line" p50_ns)"
    xdp_p90="$(field_value "$xdp_bench_line" p90_ns)"
    xdp_p95="$(field_value "$xdp_bench_line" p95_ns)"
    xdp_p99="$(field_value "$xdp_bench_line" p99_ns)"
    xdp_avg="$(field_value "$xdp_bench_line" avg_ns)"

    local kernel_core xdp_core kernel_siblings xdp_siblings
    kernel_core="$(cpu_core_id "$KERNEL_CPU")"
    xdp_core="$(cpu_core_id "$CPU")"
    kernel_siblings="$(cpu_siblings "$KERNEL_CPU")"
    xdp_siblings="$(cpu_siblings "$CPU")"

    echo
    echo "DoubleZero RX Latency Benchmark"
    printf '+------------+-----------+---------+--------+----------+----------+----------+----------+----------+----------+-------------+\n'
    printf '| %-10s | %-9s | %-7s | %-6s | %-8s | %-8s | %-8s | %-8s | %-8s | %-8s | %-11s |\n' \
        "mode" "linux_cpu" "core_id" "queue" "packets" "p50_us" "p90_us" "p95_us" "p99_us" "avg_us" "smt"
    printf '+------------+-----------+---------+--------+----------+----------+----------+----------+----------+----------+-------------+\n'
    printf '| %-10s | %-9s | %-7s | %-6s | %-8s | %-8s | %-8s | %-8s | %-8s | %-8s | %-11s |\n' \
        "udp_kernel" "$KERNEL_CPU" "$kernel_core" "kernel" "${kernel_packets:-n/a}" \
        "$(ns_to_us "${kernel_p50:-}")" "$(ns_to_us "${kernel_p90:-}")" "$(ns_to_us "${kernel_p95:-}")" "$(ns_to_us "${kernel_p99:-}")" "$(ns_to_us "${kernel_avg:-}")" "$kernel_siblings"
    printf '| %-10s | %-9s | %-7s | %-6s | %-8s | %-8s | %-8s | %-8s | %-8s | %-8s | %-11s |\n' \
        "xdp_af_xdp" "$CPU" "$xdp_core" "$QUEUE" "${xdp_packets:-n/a}" \
        "$(ns_to_us "${xdp_p50:-}")" "$(ns_to_us "${xdp_p90:-}")" "$(ns_to_us "${xdp_p95:-}")" "$(ns_to_us "${xdp_p99:-}")" "$(ns_to_us "${xdp_avg:-}")" "$xdp_siblings"
    printf '+------------+-----------+---------+--------+----------+----------+----------+----------+----------+----------+-------------+\n'
}

echo "[*] Building DoubleZero RX binaries..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" \
    --release \
    --bin doublezero_kernel_rx \
    --bin doublezero_xdp_rx >/dev/null

truncate -s 0 "$KERNEL_LOG"
if (( RUN_KERNEL == 1 )); then
    wait_for_kernel_path_ready
    echo "[*] Running kernel-stack DoubleZero RX for ${BENCH_DURATION_SECS}s..."
    "$KERNEL_BIN" \
        --iface "$KERNEL_IFACE" \
        --group "$KERNEL_GROUP" \
        --port "$KERNEL_PORT" \
        --cpu "$KERNEL_CPU" \
        --duration-secs "$BENCH_DURATION_SECS" \
        --packet-log-limit "$KERNEL_PACKET_LOG_LIMIT" \
        --recv-buffer-mb "$KERNEL_RECV_BUFFER_MB" \
        >"$KERNEL_LOG" 2>&1
else
    echo "kernel_rx_skipped reason=interface_not_found iface=${KERNEL_IFACE}" >"$KERNEL_LOG"
fi

truncate -s 0 "$XDP_LOG"
truncate -s 0 /tmp/doublezero-rx-bench-xdp-launcher.log
if (( RUN_XDP == 1 )); then
    echo "[*] Running XDP/AF_XDP DoubleZero RX for ${BENCH_DURATION_SECS}s..."
    stop_pid_file /tmp/doublezero-rx.pid
    DEV="$DEV" QUEUE="$QUEUE" CPU="$CPU" ATTACH_MODE="$ATTACH_MODE" LOG="$XDP_LOG" BIN="$XDP_BIN" \
        RX_PATH_BENCH=1 PACKET_LOG_LIMIT="$XDP_PACKET_LOG_LIMIT" \
        "$XDP_SCRIPT" >/tmp/doublezero-rx-bench-xdp-launcher.log 2>&1 &
    XDP_LAUNCHER_PID="$!"
    wait_for_log_pattern /tmp/doublezero-rx-bench-xdp-launcher.log "fdir:" 25 "XDP launcher" "$XDP_LAUNCHER_PID"
    sleep "$BENCH_DURATION_SECS"
    kill "$XDP_LAUNCHER_PID" 2>/dev/null || true
    wait "$XDP_LAUNCHER_PID" 2>/dev/null || true
    stop_pid_file /tmp/doublezero-rx.pid
else
    echo "xdp_rx_skipped reason=bench_mode_${BENCH_MODE}" >"$XDP_LOG"
fi

echo
echo "DoubleZero RX benchmark artifacts:"
echo "  kernel log: $KERNEL_LOG"
echo "  xdp log:    $XDP_LOG"
echo "  xdp launcher log: /tmp/doublezero-rx-bench-xdp-launcher.log"
echo
summarize_final "kernel" "$KERNEL_LOG"
summarize_final "xdp" "$XDP_LOG"
print_table
