use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::io::Result;

const BUFFER_SIZE: usize = 65536; // 64KB

pub async fn tunnel_connect(mut client: TcpStream, mut target: TcpStream) -> Result<()> {
    let (mut client_read, mut client_write) = client.split();
    let (mut target_read, mut target_write) = target.split();
    
    let client_to_target = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = target_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if target_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };
    
    let target_to_client = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = client_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };
    
    tokio::select! {
        _ = client_to_target => {},
        _ = target_to_client => {},
    }
    
    Ok(())
}