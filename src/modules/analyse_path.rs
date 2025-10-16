/// In test and development, very basic.

use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Protocol {
    pub name: String,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct UniqueIp {
    pub src: String,
}

fn classify_threat(count: usize, threshold: f64) -> &'static str {
    let ratio = count as f64 / threshold;
    if ratio > 3.0 {
        "Critical"
    } else if ratio > 2.0 {
        "High"
    } else {
        "Moderate"
    }
}

pub fn analyse_path(
    counts_ip: HashMap<UniqueIp, usize>,
    counts_pro: HashMap<Protocol, usize>,
    _layers: Option<&rtshark::Packet>
) {
    println!("\n=== Path Analysis ===\n");

    let total_packets: usize = counts_ip.values().sum();
    let average = total_packets as f64 / counts_ip.len() as f64;
    let threshold = average * 2.0; // IPs with twice the average number of packets

    println!("Statistics:");
    println!("  - Total packets: {}", total_packets);
    println!("  - Average per IP: {:.2}", average);
    println!("  - Suspicion threshold: {:.2}\n", threshold);

    let mut suspicious_ips: Vec<(&UniqueIp, &usize)> = counts_ip
        .iter()
        .filter(|&(_, &count)| count as f64 > threshold)
        .collect();

    suspicious_ips.sort_by(|a, b| b.1.cmp(a.1)); // Sort by packet count (descending)

    if suspicious_ips.is_empty() {
        println!("No suspicious IPs detected.");
    } else {
        println!("SUSPICIOUS IPs DETECTED ({}):\n", suspicious_ips.len());

        for (rank, (ip, count)) in suspicious_ips.iter().enumerate() {
            let deviation = (**count as f64 / average - 1.0) * 100.0;
            println!("{}. IP: {}", rank + 1, ip.src);
            println!("   └─ Packets: {} ({:.0}% above average)", count, deviation);
            println!("   └─ Threat level: {}", classify_threat(**count, threshold));
            println!();
        }
    }
}
