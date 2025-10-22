// Network Rule Detection
#[derive(Clone, Debug)]
pub struct NetworkEvent {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
    pub info: String,
    pub file_hash: Option<String>,
}

pub struct ICMP {
    pub content_lenght: usize,
}

impl NetworkEvent {
    pub fn new(timestamp: String, src_ip: String, dst_ip: String, protocol: String) -> Self {
        Self {
            timestamp,
            src_ip,
            dst_ip,
            protocol,
            src_port: None,
            dst_port: None,
            info: String::new(),
            file_hash: None,
        }
    }

    pub fn detect_os_by_ttl(ttl: u8) -> &'static str {
        if ttl == 64 || ttl == 63 {
            return "linux/mac";
        }

        if ttl == 128 {
            return "windows";
        }
        return "unknown"
    }
}

impl ICMP {
    pub fn is_valid(&self) -> bool {
        // Max content lenght is 70 bytes for data field
        if self.content_lenght >= 70 {
            return false;
        }
        true
    }
}