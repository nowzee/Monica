// Network Rule Detection
pub struct NetworkRule {
    pub ttl: u8
}

pub struct ICMP {
    pub content_lenght: usize,
}

impl NetworkRule {

    pub fn detect_os_by_ttl(&self) -> &str {
        if self.ttl == 64 || self.ttl == 63 {
            return "linux/mac";
        }

        if self.ttl == 128 {
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