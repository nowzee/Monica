/// Network traffic analysis module for threat detection and attack chain reconstruction.

use std::collections::{HashMap, HashSet};
use sha2::{Sha256, Digest};
use std::sync::OnceLock;

#[path = "../../modules/rules.rs"]
mod rules;
use rules::{ICMP, NetworkEvent};

static DEBUG_CHAIN: OnceLock<bool> = OnceLock::new();


pub fn set_debug_chain(value: bool) {
    DEBUG_CHAIN.set(value).unwrap();
}

pub fn get_debug_chain() -> bool {
    *DEBUG_CHAIN.get().unwrap_or(&false)
}

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

fn extract_packet_info(packet: rtshark::Packet) -> PacketInfo {
    let mut packet_info = PacketInfo::new();

    for layer in packet {
        for metadata in layer {
            // check_icmp_packet(&metadata);
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
    }

    packet_info
}

/// Extract detailed network event from packet, returning event and raw file data
fn extract_network_event_with_data(packet: rtshark::Packet) -> Option<(NetworkEvent, Option<String>)> {
    let mut timestamp = String::from("0.000s");
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut protocol = String::from("Unknown");
    let mut src_port = None;
    let mut dst_port = None;
    let mut dns_query = None;
    let mut http_request = None;
    let mut http_method = None;
    let mut tcp_flags = None;
    let mut file_data = None;

    for layer in packet {
        let layer_name = layer.name().to_string();
        
        for metadata in layer {
            match metadata.name() {
                "frame.time_relative" => timestamp = format!("{:.3}s", metadata.value().parse::<f64>().unwrap_or(0.0)),
                "ip.src" => src_ip = Some(metadata.value().to_string()),
                "ip.dst" => dst_ip = Some(metadata.value().to_string()),
                "tcp.srcport" => src_port = Some(metadata.value().to_string()),
                "tcp.dstport" => dst_port = Some(metadata.value().to_string()),
                "udp.srcport" => src_port = Some(metadata.value().to_string()),
                "udp.dstport" => dst_port = Some(metadata.value().to_string()),
                "dns.qry.name" => dns_query = Some(metadata.value().to_string()),
                "http.request.method" => http_method = Some(metadata.value().to_string()),
                "http.request.uri" => http_request = Some(metadata.value().to_string()),
                "tcp.flags" => tcp_flags = Some(metadata.value().to_string()),
                "http.file_data" => {
                    file_data = Some(metadata.value().to_string());
                },
                _ => {}
            }
        }
        
        // Determine protocol from layer
        if layer_name == "tcp" {
            protocol = String::from("TCP");
        } else if layer_name == "udp" {
            protocol = String::from("UDP");
        } else if layer_name == "icmp" {
            protocol = String::from("ICMP");
        } else if layer_name == "dns" {
            protocol = String::from("DNS");
        } else if layer_name == "http" {
            protocol = String::from("HTTP");
        }
    }

    let src = src_ip?;
    let dst = dst_ip?;

    let mut event = NetworkEvent::new(timestamp, src, dst, protocol.clone());
    event.src_port = src_port.clone();
    event.dst_port = dst_port.clone();

    // Build descriptive info
    let mut info_parts = Vec::new();
    
    if let Some(method) = http_method {
        if let Some(uri) = http_request {
            info_parts.push(format!("{} {}", method, uri));
        }
    } else if let Some(query) = dns_query {
        info_parts.push(format!("Query: {}", query));
    } else if let Some(flags) = tcp_flags {
        info_parts.push(format!("Flags: {}", flags));
    }

    if let (Some(sp), Some(dp)) = (&event.src_port, &event.dst_port) {
        info_parts.push(format!("{}:{} -> {}:{}", event.src_ip, sp, event.dst_ip, dp));
    }

    event.info = info_parts.join(" | ");

    Some((event, file_data))
}

fn handle_os_detection(packet_info: &PacketInfo, os_seen: &mut HashSet<CheckOs>) {
    if let (Some(ttl), Some(src)) = (packet_info.ttl, &packet_info.src_ip) {
        let os_check = CheckOs {
            src: src.clone(),
            ttl_os: ttl,
        };

        if os_seen.insert(os_check) {
            let os = NetworkEvent::detect_os_by_ttl(ttl);

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


/// Not optimised, need a hashmap or vec
fn analyse_packets(file_path: &str, suspicious_set: HashSet<String>) {
    let builder = rtshark::RTSharkBuilder::builder().input_path(file_path);
    let mut rtshark = builder.spawn().unwrap();

    let mut os_seen: HashSet<CheckOs> = HashSet::new();

    println!("=== OS Detection ===\n");
    while let Some(packet) = rtshark.read().expect("Failed to read packet") {
        let packet_info = extract_packet_info(packet);
        handle_os_detection(&packet_info, &mut os_seen);
    }

    if get_debug_chain() {
        let builder = rtshark::RTSharkBuilder::builder().input_path(file_path);
        let mut rtshark = builder.spawn().unwrap();
        println!("\n=== Suspicious traffic ===");
        while let Some(packet) = rtshark.read().unwrap() {
            let packet_info = extract_packet_info(packet);
            log_suspicious_traffic(&packet_info, &suspicious_set);
        }
    }
}

/// Build and display attack chains from network events, Not optimized for performance only for test and debug purposes actually.
fn build_attack_chains(events: Vec<NetworkEvent>) {
    if events.is_empty() {
        println!("No network events to analyze.");
        return;
    }

    println!("\n╔══════════════════════════════════════════════════════════════════=═════════════════╗");
    println!("║                           ATTACK CHAIN RECONSTRUCTION                              ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════════╝\n");

    // Group events by interactions (src -> dst pairs)
    let mut interactions: HashMap<(String, String), Vec<&NetworkEvent>> = HashMap::new();
    
    for event in &events {
        let key = (event.src_ip.clone(), event.dst_ip.clone());
        interactions.entry(key).or_insert_with(Vec::new).push(event);
    }

    // Build a map of IPs and what they communicated
    let mut ip_connections: HashMap<String, HashSet<String>> = HashMap::new();
    for event in &events {
        ip_connections.entry(event.src_ip.clone())
            .or_insert_with(HashSet::new)
            .insert(event.dst_ip.clone());
    }

    // Find potential attack initiators (IPs that contact many others)
    let mut ip_activity: Vec<(String, usize)> = ip_connections.iter()
        .map(|(ip, targets)| (ip.clone(), targets.len()))
        .collect();
    ip_activity.sort_by(|a, b| b.1.cmp(&a.1));

    println!("═══ Network Activity Summary ═══\n");
    for (ip, target_count) in ip_activity.iter().take(5) {
        println!("  • IP {} contacted {} different targets", ip, target_count);
    }

    println!("\n═══ Detailed Attack Chain ═══\n");

    let mut chain_num = 1;
    let mut processed_pairs: HashSet<(String, String)> = HashSet::new();

    // Display interactions in chronological
    for event in &events {
        let key = (event.src_ip.clone(), event.dst_ip.clone());
        let reverse_key = (event.dst_ip.clone(), event.src_ip.clone());
        
        if processed_pairs.contains(&key) {
            continue;
        }
        processed_pairs.insert(key.clone());
        processed_pairs.insert(reverse_key);

        let related_events = interactions.get(&key).unwrap();
        
        println!("┌─ Chain #{}: {} → {}", chain_num, event.src_ip, event.dst_ip);
        println!("│");

        for (idx, evt) in related_events.iter().enumerate() {
            let connector = if idx < related_events.len() - 1 { "├" } else { "└" };
            
            println!("{}─ [{}] {} {} → {}", 
                connector,
                evt.timestamp,
                evt.src_ip,
                evt.protocol,
                evt.dst_ip
            );

            if !evt.info.is_empty() {
                println!("│  └─ {}", evt.info);
            } else if let (Some(sp), Some(dp)) = (&evt.src_port, &evt.dst_port) {
                println!("│  └─ Port {}:{} → {}:{}", evt.src_ip, sp, evt.dst_ip, dp);
            }

            // Display file hash if available, tested only for HTTP GET requests
            if let Some(hash) = &evt.file_hash {
                println!("│  └─ File Hash (SHA256): {}", hash);
            }

            // Check if this destination then contacted others (chain reaction)
            if let Some(next_targets) = ip_connections.get(&evt.dst_ip) {
                let other_targets: Vec<&String> = next_targets.iter()
                    .filter(|t| *t != &evt.src_ip)
                    .collect();
                
                if !other_targets.is_empty() && idx == related_events.len() - 1 {
                    println!("│  └─ This caused {} to then contact: {}",
                        evt.dst_ip, 
                        other_targets.iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
        }
        
        println!("│");
        chain_num += 1;
    }

    println!("\n═══ Summary ═══");
    println!("  Total events analyzed: {}", events.len());
    println!("  Unique interactions: {}", interactions.len());
    println!("  Active IPs: {}", ip_connections.len());
}

/// Collect all network events from pcapng file, need optimisation
fn collect_network_events(file_path: &str) -> Vec<NetworkEvent> {
    let builder = rtshark::RTSharkBuilder::builder().input_path(file_path);
    let mut rtshark = match builder.spawn() {
        Ok(rtshark) => rtshark,
        Err(e) => {
            eprintln!("Error spawning rtshark: {}", e);
            return Vec::new();
        }
    };

    let mut events = Vec::new();
    // Track HTTP GET requests: (client_ip, server_ip, client_port, server_port) -> request event index
    let mut http_requests: HashMap<(String, String, String, String), usize> = HashMap::new();
    // Track file data by connection: (client_ip, server_ip, client_port, server_port) -> accumulated bytes
    let mut file_transfers: HashMap<(String, String, String, String), Vec<u8>> = HashMap::new();

    while let Some(packet) = rtshark.read().unwrap_or(None) {
        if let Some((event, file_data)) = extract_network_event_with_data(packet) {
            let event_idx = events.len();
            
            // Track HTTP GET requests (client -> server)
            if event.protocol == "HTTP" && event.info.starts_with("GET ") {
                if let (Some(sp), Some(dp)) = (&event.src_port, &event.dst_port) {
                    let key = (event.src_ip.clone(), event.dst_ip.clone(), sp.clone(), dp.clone());
                    http_requests.insert(key, event_idx);
                }
            }
            
            // Track file data from any packet (HTTP or TCP) that has it
            if let (Some(sp), Some(dp), Some(data)) = (&event.src_port, &event.dst_port, &file_data) {
                // Try to decode hex data
                if let Ok(bytes) = hex::decode(data.replace(":", "").replace(" ", "")) {
                    // For response packets (server -> client), create key matching the original request
                    let forward_key = (event.dst_ip.clone(), event.src_ip.clone(), dp.clone(), sp.clone());
                    let reverse_key = (event.src_ip.clone(), event.dst_ip.clone(), sp.clone(), dp.clone());
                    
                    // If this is a response to a known HTTP GET request, accumulate data
                    if http_requests.contains_key(&forward_key) {
                        file_transfers.entry(forward_key).or_insert_with(Vec::new).extend_from_slice(&bytes);
                    } else if http_requests.contains_key(&reverse_key) {
                        file_transfers.entry(reverse_key).or_insert_with(Vec::new).extend_from_slice(&bytes);
                    }
                }
            }
            
            events.push(event);
        }
    }

    // Calculate hashes for accumulated file transfers and assign to the GET request event
    for (key, accumulated_data) in file_transfers.iter() {
        if let Some(&event_idx) = http_requests.get(key) {
            if event_idx < events.len() && !accumulated_data.is_empty() {
                let mut hasher = Sha256::new();
                hasher.update(accumulated_data);
                let result = hasher.finalize();
                events[event_idx].file_hash = Some(format!("{:x}", result));
            }
        }
    }

    events
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

    analyse_packets(file_path, suspicious_set.clone());

    // Build and display attack chains
    println!("\n");
    let events = collect_network_events(file_path);
    build_attack_chains(events);
}