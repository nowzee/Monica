mod modules;

use rtshark;
use std::collections::HashMap;
use std::env;
use std::process::exit;
use modules::analyse_path::{Protocol, UniqueIp};


/// Analyze the pcap file.
///
/// # Arguments
/// * `file` - Modify the file to analyze.
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Argument file is missing. <file>");
        exit(0);
    }

    let file = Some(&args[1]).unwrap();
    let mut debug_chain = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--debug-chain" => debug_chain = true,
            "--help" => {
                println!("\nUsage: monica <file>");
                println!("\nOptions");
                println!("  --debug-chain   Enable debug mode but more slow.");
                exit(0);
            }
            &_ => {}
        }
    }

    modules::analyse_path::set_debug_chain(debug_chain);

    let mut counts_pro: HashMap<Protocol, usize> = HashMap::new();
    let mut count_number_of_packets: usize = 0;

    let mut counts_ip: HashMap<UniqueIp, usize> = HashMap::new();

    // Creates a builder with needed tshark parameters
    let builder = rtshark::RTSharkBuilder::builder()
        .input_path(file);

    // Start a new TShark process
    let mut rtshark = match builder.spawn() {
        Err(err) =>  { eprintln!("Error running tshark: {err}"); return }
        Ok(rtshark) => rtshark,
    };

    // Read packets until the end of the PCAP file
    while let Some(packet) = rtshark.read().unwrap() {
        for layer in packet {

            let proto = Protocol {name: layer.name().to_string()};
            *counts_pro.entry(proto).or_insert(0) += 1;
            count_number_of_packets += 1;

            for metadata in layer {
                if metadata.name() == "ip.src" {

                    let ip = UniqueIp {src: metadata.value().to_string()};
                    *counts_ip.entry(ip).or_insert(0) += 1;
                }
            }
        }
    };

    for (protocol, size) in &counts_pro {
        println!("{:?} and count : {:?}", protocol.name, size);
    }

    println!("\n\n");

    for (ip, size) in &counts_ip {
        println!("{:?} and count : {:?}", ip.src, size);
    }

    println!("\n\nNumber of packets: {}", count_number_of_packets);

    modules::analyse_path::analyse_path(counts_ip, counts_pro, file);
}
