/// In test and development, very basic.

use std::collections::HashMap;
use std::collections::HashSet;

#[derive(PartialEq, Eq, Hash)]
pub struct Protocol {
    pub name: String,
}

#[derive(PartialEq, Eq, Hash)]
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
    _counts_pro: HashMap<Protocol, usize>,
    file_path: &str,
) {

    // This is a very basic analysis for testing and future development purposes..
    println!("\n=== Path Analysis ===\n");

    let total_packets: usize = counts_ip.values().sum();
    let average = total_packets as f64 / counts_ip.len() as f64;
    let threshold = average * 1.5; // IPs with twice the average number of packets

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

    let suspicious_set: HashSet<String> = suspicious_ips
        .iter()
        .map(|(ip, _)| ip.src.clone())
        .collect();

    let builder = rtshark::RTSharkBuilder::builder()
        .input_path(file_path);

    let mut rtshark = builder.spawn().unwrap();

    while let Some(packet) = rtshark.read().unwrap() {
        let mut src_ip: Option<String> = None;
        let mut dst_ip: Option<String> = None;
        let mut domain_name: Option<String> = None;
        let mut http_request: Option<String> = None;
        let mut time_request: Option<String> = None;

        for layer in packet {
            for metadata in layer {
                match metadata.name() {
                    "ip.src" => src_ip = Some(metadata.value().to_string()),
                    "ip.dst" => dst_ip = Some(metadata.value().to_string()),
                    "dns.qry.name" => domain_name = Some(metadata.value().to_string()),
                    "http.request.full_uri"=> http_request = Some(metadata.value().to_string()),
                    "frame.time_utc" => time_request = Some(metadata.value().to_string()),
                    _ => {}
                }
            }
        }

        if let (Some(src), Some(dst)) = (src_ip, dst_ip) {
            if suspicious_set.contains(&src) {
                if let Some(domain) = &domain_name {
                    println!("({}) Suspicious source {} => destination {} (domain: {})",time_request.unwrap(),  src, dst, domain);
                }
                    else if let Some(request) = &http_request {
                        println!("({}) Suspicious source {} => destination {} (request: {})",time_request.unwrap(), src, dst, request);
                    }
                else {
                    println!("({}) Suspicious source {} => destination {}",time_request.unwrap(), src, dst);
                }
            }
        }
    }
}
