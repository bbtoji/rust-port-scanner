use clap::Parser;
use futures::lock::Mutex;
use futures::{self, future::join_all};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::{net::TcpStream, sync::Semaphore, time::Duration};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

#[derive(Parser, Debug)]
#[command(author = "bbtoji", about = "Rust Port Scanner")]
struct Args {
    #[arg(short, long)]
    address: String,

    #[arg(short, long, default_value_t = 1)]
    start_port: u16,

    /// Ending port number (default = 1024)
    #[arg(short, long, default_value_t = 1024)]
    end_port: u16,

    // Output file of scanning result
    #[arg(short, long)]
    output: Option<String>,
}

type VecPorts = Arc<Mutex<Vec<u16>>>;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let ip = get_ip(&args).await;
    println!(
        "[...] Start scanning IP: {} in range ({}-{})",
        ip, args.start_port, args.end_port
    );
    let range = args.start_port..=args.end_port;

    let timeout = Duration::from_secs(2);

    let max_concurrent = 128;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    let mut tasks = Vec::new();

    let ports_vector: VecPorts = Arc::new(Mutex::new(Vec::new()));

    for port in range {
        let sem = semaphore.clone();
        let ports_vec = ports_vector.clone();
        let result = tokio::spawn(scan_port(ip, port, timeout, sem, ports_vec));
        tasks.push(result);
    }
    join_all(tasks).await;
    let open_ports = ports_vector.lock().await.clone();
    if let Some(output) = args.output {
        write_result(output, open_ports).await.unwrap();
    }
}

async fn get_ip(args: &Args) -> IpAddr {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let response = resolver
        .lookup_ip(&args.address)
        .await
        .expect("[!] Failed to resolve domain name.");
    response.iter().next().expect("[!] No addresses returned.")
}

async fn scan_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    sem: Arc<Semaphore>,
    ports_vec: VecPorts,
) {
    let permit = sem.acquire_owned().await.unwrap();
    let addr = format!("{ip}:{port}");
    if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        println!("[✓] Port {} is open", port);
        ports_vec.lock().await.push(port);
    }
    drop(permit);
}

async fn write_result(file: String, ports: Vec<u16>) -> std::io::Result<()> {
    let filepath = Path::new(&file);
    let mut output = File::create(filepath).await?;
    output.write_all(b"Scan result:\n").await?;
    for port in ports {
        output.write_all(port.to_string().as_bytes()).await?;
        output.write_all(b" ").await?;
    }
    output.write_all(b"\n").await?;
    Ok(())
}
