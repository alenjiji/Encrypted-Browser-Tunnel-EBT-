use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use std::sync::Arc;

pub struct TunnelStats {
    pub active_tunnels: AtomicU32,
    pub total_tunnels: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl TunnelStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active_tunnels: AtomicU32::new(0),
            total_tunnels: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        })
    }
    
    pub fn tunnel_started(&self) {
        self.active_tunnels.fetch_add(1, Ordering::Relaxed);
        self.total_tunnels.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn tunnel_closed(&self, bytes_in: u64, bytes_out: u64) {
        self.active_tunnels.fetch_sub(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }
    
    pub fn print_stats(&self) {
        let active = self.active_tunnels.load(Ordering::Relaxed);
        let total = self.total_tunnels.load(Ordering::Relaxed);
        let bytes_in = self.bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.bytes_out.load(Ordering::Relaxed);
        
        println!("[stats] active={} total={} bytes_in={:.1}MB bytes_out={:.1}MB", 
                 active, total, bytes_in as f64 / 1_048_576.0, bytes_out as f64 / 1_048_576.0);
    }
}