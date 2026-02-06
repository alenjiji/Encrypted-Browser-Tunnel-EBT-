use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing");
    let obs_dir = Path::new(&manifest_dir).join("src").join("core").join("observability");
    if obs_dir.exists() {
        let mut files = Vec::new();
        collect_rs_files(&obs_dir, &mut files);
        for path in files {
            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
            enforce_observability_guards(&contents, &path);
        }
    }
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, files);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

fn enforce_observability_guards(contents: &str, path: &Path) {
    let forbidden = [
        "chrono",
        "std::net",
        "SocketAddr",
        "IpAddr",
        "relay_protocol",
        "SystemTime",
        "Instant",
        "log!(",
        "println!(",
        "eprintln!(",
    ];

    for token in forbidden {
        if contents.contains(token) {
            panic!(
                "Forbidden token `{}` in observability module: {}",
                token,
                path.display()
            );
        }
    }
}
