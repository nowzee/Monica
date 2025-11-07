mod modules;

use rtshark::RTSharkBuilder;
use std::collections::HashMap;
use std::env;
use std::process::exit;
use modules::wireshark::analyse_path::{Protocol, UniqueIp, set_debug_chain, analyse_path};


fn main() {
    let args: Vec<String> = env::args().collect();

    let mut debug_chain = false;
    let mut mode: String = "None".to_string();

    if args.contains(&"--help".to_string()) {
        println!("\nUsage: ./Monica <file> --mode wireshark");
        println!("  <file>          The file to analyze.");
        println!("\nMonica is a tool to find attack path and more..");
        println!("\nOptions:");
        println!("  --debug-chain   Enable debug mode but more slow.");
        println!("  --mode          wireshark, soon autodetect mode by default.");
        println!("  --help          Show this help message and exit.\n\n");
        exit(0);
    }


    if args.len() == 1 {
        println!("\nMonica: error: the following arguments are required: <file>, --mode");
        exit(0);
    } else if args.len() < 2 {
        println!("Argument file is missing. <file>");
    }

    if !args.iter().any(|arg| arg == "--mode") {
        println!("Argument --mode is missing.");
        exit(1)
    } else {
        if let Some(pos) = args.iter().position(|arg| arg == "--mode") {

            let mode_pos = &args[pos + 1].as_str();

            if !["wireshark"].contains(mode_pos) {
                println!("Invalid mode. only (wireshark) is supported.");
                exit(1)
            } else {
                mode = mode_pos.to_string();
            }

        }
    }

    let file = Some(&args[1]).unwrap();

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "--debug-chain" => debug_chain = true,
            &_ => {}
        }
    }

    set_debug_chain(debug_chain);

    if mode == "wireshark" {
        let mut counts_pro: HashMap<Protocol, usize> = HashMap::new();
        let mut count_number_of_packets: usize = 0;

        let mut counts_ip: HashMap<UniqueIp, usize> = HashMap::new();

        // Creates a builder with needed tshark parameters
        let builder = RTSharkBuilder::builder()
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

        analyse_path(counts_ip, counts_pro, file);
    }
}
