# Encrypted Browser Tunnel - Rust Implementation

A minimal Rust project skeleton implementing the conceptual architecture documented in `Documentation/`.

## Project Structure

```
src/
├── main.rs      # Entry point
├── client.rs    # Client device component
├── proxy.rs     # Proxy/relay node component  
├── transport.rs # Encrypted transport layer abstraction
└── dns.rs       # DNS resolution handling
```

## Architecture Components

- **Client**: Represents browser/application with proxy configuration
- **ProxyRelay**: Intermediary server for traffic forwarding
- **EncryptedTransport**: Trait for SSH/TLS/QUIC transport layers
- **DnsResolver**: Local vs remote DNS resolution with leak detection

## Project Purpose

This skeleton demonstrates the architectural concepts from the documentation without implementing actual network behavior. Each component contains placeholder methods that log their intended functionality.

## Running

```bash
cargo run
```

## Note

This tool is designed for learning network architecture concepts. No actual network connections are established.
