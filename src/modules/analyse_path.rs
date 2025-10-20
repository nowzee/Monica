/// Network traffic analysis module for threat detection, very basic in dev and not optimized for test.

use std::collections::{HashMap, HashSet};

#[path = "../modules/rules.rs"]
mod rules;
use rules::{ICMP, NetworkRule};

#[derive(PartialEq, Eq, Hash)]
pub struct Protocol {
    pub name: String,
}

#[derive(PartialEq, Eq, Hash)]
pub struct UniqueIp {
    pub src: String,
}

#[derive(PartialEq, Eq, Hash)]
struct CheckOs {
    src: String,
    ttl_os: u8
}

struct PacketInfo {
    src_ip: Option<String>,
    dst_ip: Option<String>,
    domain_name: Option<String>,
    http_request: Option<String>,
    time_request: Option<String>,
    ttl: Option<u8>,
}

impl PacketInfo {
    fn new() -> Self {
        Self {
            src_ip: None,
            dst_ip: None,
            domain_name: None,
            http_request: None,
            time_request: None,
            ttl: None,
        }
    }
}

fn classify_threat(count: usize, threshold: f64) -> &'static str {
    let ratio = count as f64 / threshold;
    match ratio {
        r if r > 3.0 => "Critical",
        r if r > 2.0 => "High",
        _ => "Moderate",
    }
}

fn print_statistics(total_packets: usize, average: f64, threshold: f64) {
    println!("\n=== Path Analysis ===\n");
    println!("Statistics:");
    println!("  - Total packets: {}", total_packets);
    println!("  - Average per IP: {:.2}", average);
    println!("  - Suspicion threshold: {:.2}\n", threshold);
}

fn print_suspicious_ips(suspicious_ips: &[(&UniqueIp, &usize)], average: f64, threshold: f64) {
    if suspicious_ips.is_empty() {
        println!("No suspicious IPs detected.");
        return;
    }

    println!("SUSPICIOUS IPs DETECTED ({}):\n", suspicious_ips.len());
    for (rank, (ip, count)) in suspicious_ips.iter().enumerate() {
        let deviation = (**count as f64 / average - 1.0) * 100.0;
        println!("{}. IP: {}", rank + 1, ip.src);
        println!("   └─ Packets: {} ({:.0}% above average)", count, deviation);
        println!("   └─ Threat level: {}\n", classify_threat(**count, threshold));
    }
}

fn get_suspicious_ips(counts_ip: &HashMap<UniqueIp, usize>, threshold: f64) -> Vec<(&UniqueIp, &usize)> {
    let mut suspicious_ips: Vec<(&UniqueIp, &usize)> = counts_ip
        .iter()
        .filter(|&(_, &count)| count as f64 > threshold)
        .collect();

    suspicious_ips.sort_by(|a, b| b.1.cmp(a.1));
    suspicious_ips
}

fn check_icmp_packet(metadata: &rtshark::Metadata) {
    if metadata.name() != "icmp.data" {
        return;
    }

    let icmp = ICMP {
        content_lenght: metadata.value().len(),
    };

    if !icmp.is_valid() {
        println!("BAD ICMP packet detected");
        println!("ICMP packet length content: {}", metadata.value().len());
    }
}

fn process_metadata(packet_info: &mut PacketInfo, metadata: &rtshark::Metadata) {
    match metadata.name() {
        "ip.src" => packet_info.src_ip = Some(metadata.value().to_string()),
        "ip.dst" => packet_info.dst_ip = Some(metadata.value().to_string()),
        "dns.qry.name" => packet_info.domain_name = Some(metadata.value().to_string()),
        "http.request.full_uri" => packet_info.http_request = Some(metadata.value().to_string()),
        "frame.time_utc" => packet_info.time_request = Some(metadata.value().to_string()),
        "ip.ttl" => {
            if let Ok(ttl_value) = metadata.value().parse::<u8>() {
                packet_info.ttl = Some(ttl_value);
            }
        }
        _ => {}
    }
}

fn extract_packet_info(packet: rtshark::Packet) -> PacketInfo {
    let mut packet_info = PacketInfo::new();

    for layer in packet {
        for metadata in layer {
            // check_icmp_packet(&metadata);
            process_metadata(&mut packet_info, &metadata);
        }
    }

    packet_info
}

fn handle_os_detection(packet_info: &PacketInfo, os_seen: &mut HashSet<CheckOs>) {
    if let (Some(ttl), Some(src)) = (packet_info.ttl, &packet_info.src_ip) {
        let os_check = CheckOs {
            src: src.clone(),
            ttl_os: ttl,
        };

        if os_seen.insert(os_check) {
            let rule = NetworkRule { ttl };
            let os = rule.detect_os_by_ttl();

            if os != "unknown" {
                println!("IP: {}", src);
                println!("OS {:?}", os);
                println!("TTL: {}", ttl);
            }
        }
    }
}

fn log_suspicious_traffic(packet_info: &PacketInfo, suspicious_set: &HashSet<String>) {
    let (Some(src), Some(dst)) = (&packet_info.src_ip, &packet_info.dst_ip) else {
        return;
    };

    if !suspicious_set.contains(src) {
        return;
    }

    let time = packet_info.time_request.as_deref().unwrap_or("unknown");

    if let Some(domain) = &packet_info.domain_name {
        println!("({}) Suspicious source {} => destination {} (domain: {})", time, src, dst, domain);
    } else if let Some(request) = &packet_info.http_request {
        println!("({}) Suspicious source {} => destination {} (request: {})", time, src, dst, request);
    } else {
        println!("({}) Suspicious source {} => destination {}", time, src, dst);
    }
}

fn analyse_packets(file_path: &str, suspicious_set: HashSet<String>) {
    let builder = rtshark::RTSharkBuilder::builder().input_path(file_path);
    let mut rtshark = builder.spawn().unwrap();

    let mut os_seen: HashSet<CheckOs> = HashSet::new();

    println!("=== OS Detection ===\n");
    while let Some(packet) = rtshark.read().expect("Failed to read packet") {
        let packet_info = extract_packet_info(packet);
        handle_os_detection(&packet_info, &mut os_seen);
    }

    {
        let builder = rtshark::RTSharkBuilder::builder().input_path(file_path);
        let mut rtshark = builder.spawn().unwrap();

        println!("\n=== Suspicious traffic ===");
        while let Some(packet) = rtshark.read().unwrap() {
            let packet_info = extract_packet_info(packet);
            log_suspicious_traffic(&packet_info, &suspicious_set);
        }
    }
}

pub fn analyse_path(
    counts_ip: HashMap<UniqueIp, usize>,
    _counts_pro: HashMap<Protocol, usize>,
    file_path: &str,
) {
    let total_packets: usize = counts_ip.values().sum();
    let average = total_packets as f64 / counts_ip.len() as f64;
    let threshold = average * 1.5;

    print_statistics(total_packets, average, threshold);

    let suspicious_ips = get_suspicious_ips(&counts_ip, threshold);
    print_suspicious_ips(&suspicious_ips, average, threshold);

    let suspicious_set: HashSet<String> = suspicious_ips
        .iter()
        .map(|(ip, _)| ip.src.clone())
        .collect();

    analyse_packets(file_path, suspicious_set);
}