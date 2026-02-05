use std::process::Command;

fn main() {
    println!("Testing Phase 5 feature gate...");
    
    // Test with feature disabled (default)
    let output = Command::new("rustc")
        .args(&["--crate-type", "lib", "src/traffic_shaping.rs", "--print", "cfg"])
        .output()
        .expect("Failed to run rustc");
    
    println!("Feature disabled: {:?}", String::from_utf8_lossy(&output.stdout));
    
    // Test with feature enabled
    let output = Command::new("rustc")
        .args(&["--crate-type", "lib", "src/traffic_shaping.rs", "--cfg", "feature=\"phase_5_traffic_shaping\"", "--print", "cfg"])
        .output()
        .expect("Failed to run rustc");
    
    println!("Feature enabled: {:?}", String::from_utf8_lossy(&output.stdout));
    
    println!("Phase 5 feature gate test complete!");
}