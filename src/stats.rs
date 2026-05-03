use std::{
    fs,
    time::{Duration, Instant},
};

/// Latency histogram with microsecond buckets
pub struct LatencyHistogram {
    buckets: Vec<u64>,
    max_us: usize,
    count: u64,
    sum_us: u64,
    min_us: u64,
    max_recorded_us: u64,
}

impl LatencyHistogram {
    pub fn new(max_us: usize) -> Self {
        Self {
            buckets: vec![0; max_us + 1],
            max_us,
            count: 0,
            sum_us: 0,
            min_us: u64::MAX,
            max_recorded_us: 0,
        }
    }

    pub fn record(&mut self, latency_ns: u64) {
        let us = (latency_ns / 1000) as usize;
        let us_u64 = us as u64;

        self.count += 1;
        self.sum_us += us_u64;
        self.min_us = self.min_us.min(us_u64);
        self.max_recorded_us = self.max_recorded_us.max(us_u64);

        let bucket_idx = us.min(self.max_us);
        self.buckets[bucket_idx] += 1;
    }

    pub fn percentile(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }

        let target = ((self.count as f64) * p) as u64;
        let mut cumulative = 0u64;

        for (us, &count) in self.buckets.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                return us as u64;
            }
        }

        self.max_recorded_us
    }

    pub fn mean(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.sum_us / self.count
        }
    }

    pub fn min(&self) -> u64 {
        if self.count == 0 { 0 } else { self.min_us }
    }

    pub fn max(&self) -> u64 {
        self.max_recorded_us
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn reset(&mut self) {
        self.buckets.fill(0);
        self.count = 0;
        self.sum_us = 0;
        self.min_us = u64::MAX;
        self.max_recorded_us = 0;
    }
}

/// CPU statistics for a specific core
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuStats {
    pub user_pct: f64,
    pub system_pct: f64,
    pub idle_pct: f64,
    pub total_pct: f64,
}

/// Track CPU usage for a specific core by reading /proc/stat
pub struct CpuTracker {
    core_id: usize,
    last_user: u64,
    last_nice: u64,
    last_system: u64,
    last_idle: u64,
    last_iowait: u64,
    last_irq: u64,
    last_softirq: u64,
    last_steal: u64,
}

impl CpuTracker {
    pub fn new(core_id: usize) -> std::io::Result<Self> {
        let (user, nice, system, idle, iowait, irq, softirq, steal) =
            Self::read_cpu_times(core_id)?;

        Ok(Self {
            core_id,
            last_user: user,
            last_nice: nice,
            last_system: system,
            last_idle: idle,
            last_iowait: iowait,
            last_irq: irq,
            last_softirq: softirq,
            last_steal: steal,
        })
    }

    fn read_cpu_times(core_id: usize) -> std::io::Result<(u64, u64, u64, u64, u64, u64, u64, u64)> {
        let content = fs::read_to_string("/proc/stat")?;
        let target_line = format!("cpu{} ", core_id);

        for line in content.lines() {
            if line.starts_with(&target_line) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 9 {
                    let user = parts[1].parse().unwrap_or(0);
                    let nice = parts[2].parse().unwrap_or(0);
                    let system = parts[3].parse().unwrap_or(0);
                    let idle = parts[4].parse().unwrap_or(0);
                    let iowait = parts[5].parse().unwrap_or(0);
                    let irq = parts[6].parse().unwrap_or(0);
                    let softirq = parts[7].parse().unwrap_or(0);
                    let steal = parts[8].parse().unwrap_or(0);
                    return Ok((user, nice, system, idle, iowait, irq, softirq, steal));
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("CPU{} not found in /proc/stat", core_id),
        ))
    }

    pub fn get_usage(&mut self) -> std::io::Result<CpuStats> {
        let (user, nice, system, idle, iowait, irq, softirq, steal) =
            Self::read_cpu_times(self.core_id)?;

        let user_diff = user.saturating_sub(self.last_user);
        let nice_diff = nice.saturating_sub(self.last_nice);
        let system_diff = system.saturating_sub(self.last_system);
        let idle_diff = idle.saturating_sub(self.last_idle);
        let iowait_diff = iowait.saturating_sub(self.last_iowait);
        let irq_diff = irq.saturating_sub(self.last_irq);
        let softirq_diff = softirq.saturating_sub(self.last_softirq);
        let steal_diff = steal.saturating_sub(self.last_steal);

        let total_diff = user_diff
            + nice_diff
            + system_diff
            + idle_diff
            + iowait_diff
            + irq_diff
            + softirq_diff
            + steal_diff;

        let stats = if total_diff > 0 {
            let user_time = user_diff + nice_diff;
            let system_time = system_diff + irq_diff + softirq_diff;
            let idle_time = idle_diff + iowait_diff;

            CpuStats {
                user_pct: (user_time as f64 / total_diff as f64) * 100.0,
                system_pct: (system_time as f64 / total_diff as f64) * 100.0,
                idle_pct: (idle_time as f64 / total_diff as f64) * 100.0,
                total_pct: ((user_time + system_time) as f64 / total_diff as f64) * 100.0,
            }
        } else {
            CpuStats::default()
        };

        self.last_user = user;
        self.last_nice = nice;
        self.last_system = system;
        self.last_idle = idle;
        self.last_iowait = iowait;
        self.last_irq = irq;
        self.last_softirq = softirq;
        self.last_steal = steal;

        Ok(stats)
    }
}

/// Comprehensive statistics collector for benchmarking
pub struct StatsCollector {
    // Packet counters
    pub total_packets: u64,
    pub validated_packets: u64,
    pub corrupt_packets: u64,
    pub bytes_received: u64,

    // Interval tracking
    interval_packets: u64,
    interval_bytes: u64,
    interval_start: Instant,

    // Latency tracking
    pub one_way_latency: LatencyHistogram,
    pub processing_latency: LatencyHistogram,

    // CPU tracking
    cpu_tracker: Option<CpuTracker>,
}

impl StatsCollector {
    pub fn new(cpu_id: Option<usize>) -> Self {
        let cpu_tracker = cpu_id.and_then(|id| CpuTracker::new(id).ok());

        Self {
            total_packets: 0,
            validated_packets: 0,
            corrupt_packets: 0,
            bytes_received: 0,
            interval_packets: 0,
            interval_bytes: 0,
            interval_start: Instant::now(),
            one_way_latency: LatencyHistogram::new(100_000), // up to 100ms
            processing_latency: LatencyHistogram::new(10_000), // up to 10ms
            cpu_tracker,
        }
    }

    pub fn record_packet(&mut self, bytes: usize, validated: bool) {
        self.total_packets += 1;
        self.interval_packets += 1;
        self.bytes_received += bytes as u64;
        self.interval_bytes += bytes as u64;

        if validated {
            self.validated_packets += 1;
        } else {
            self.corrupt_packets += 1;
        }
    }

    pub fn record_one_way_latency_ns(&mut self, latency_ns: u64) {
        self.one_way_latency.record(latency_ns);
    }

    pub fn record_processing_latency(&mut self, duration: Duration) {
        self.processing_latency.record(duration.as_nanos() as u64);
    }

    pub fn should_report(&self, interval: Duration) -> bool {
        self.interval_start.elapsed() >= interval
    }

    pub fn report(&mut self, label: &str) -> String {
        let elapsed = self.interval_start.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();

        let pps = if elapsed_secs > 0.0 {
            self.interval_packets as f64 / elapsed_secs
        } else {
            0.0
        };

        let gbps = if elapsed_secs > 0.0 {
            (self.interval_bytes as f64 * 8.0) / (elapsed_secs * 1e9)
        } else {
            0.0
        };

        let cpu_stats = self
            .cpu_tracker
            .as_mut()
            .and_then(|t| t.get_usage().ok())
            .unwrap_or_default();

        let mut output = format!(
            "[{}] pkts={:<12} valid={:<12} corrupt={:<8} | {:>10.0} pps | {:>6.2} Gbps",
            label, self.total_packets, self.validated_packets, self.corrupt_packets, pps, gbps
        );

        if self.one_way_latency.count() > 0 {
            output.push_str(&format!(
                "\n[{}]   one-way latency (µs): min={:<6} avg={:<6} p50={:<6} p99={:<6} max={:<6}",
                label,
                self.one_way_latency.min(),
                self.one_way_latency.mean(),
                self.one_way_latency.percentile(0.50),
                self.one_way_latency.percentile(0.99),
                self.one_way_latency.max(),
            ));
        }

        if self.processing_latency.count() > 0 {
            output.push_str(&format!(
                "\n[{}]   processing latency (µs): min={:<6} avg={:<6} p50={:<6} p99={:<6} max={:<6}",
                label,
                self.processing_latency.min(),
                self.processing_latency.mean(),
                self.processing_latency.percentile(0.50),
                self.processing_latency.percentile(0.99),
                self.processing_latency.max(),
            ));
        }

        output.push_str(&format!(
            "\n[{}]   CPU: user={:>5.1}% sys={:>5.1}% idle={:>5.1}% total={:>5.1}%",
            label,
            cpu_stats.user_pct,
            cpu_stats.system_pct,
            cpu_stats.idle_pct,
            cpu_stats.total_pct
        ));

        // Reset interval counters
        self.interval_packets = 0;
        self.interval_bytes = 0;
        self.interval_start = Instant::now();

        output
    }

    pub fn reset_latency_histograms(&mut self) {
        self.one_way_latency.reset();
        self.processing_latency.reset();
    }
}
