use clap::{Parser, Subcommand};
use flux_app::{ConfigFormat, Instance, load_any_config};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{Level, error, info};

#[derive(Parser)]
#[command(
    name = "flux-core",
    author = "flux team",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-performance asynchronous proxy core in Rust",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy core with the specified configuration file
    Run {
        /// Path to configuration file (.json, .jsonc, .yaml, .yml)
        #[arg(short, long)]
        config: PathBuf,
        /// Config format: auto, json, yaml
        #[arg(short, long, default_value = "auto")]
        format: String,
        /// Number of worker threads (default: all CPU cores)
        #[arg(short, long)]
        workers: Option<usize>,
    },
    /// Validate configuration file without starting listeners
    Check {
        /// Path to configuration file (.json, .jsonc, .yaml, .yml)
        #[arg(short, long)]
        config: PathBuf,
        /// Config format: auto, json, yaml
        #[arg(short, long, default_value = "auto")]
        format: String,
    },
    /// Trace how a target destination will be routed through the rules
    Trace {
        /// Path to configuration file (.json, .jsonc, .yaml, .yml)
        #[arg(short, long)]
        config: PathBuf,
        /// Destination address to simulate (e.g. "google.com:443" or "1.1.1.1:53")
        #[arg(short, long)]
        destination: String,
        /// Network protocol: tcp or udp (default: tcp)
        #[arg(short, long, default_value = "tcp")]
        network: String,
        /// Inbound tag (default: "default")
        #[arg(short, long, default_value = "default")]
        inbound: String,
        /// Config format: auto, json, yaml
        #[arg(short, long, default_value = "auto")]
        format: String,
    },
    /// Print detailed version information
    Version,
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        // Restrict glibc heap arenas to eliminate multi-megabyte arena fragmentation
        libc::mallopt(libc::M_ARENA_MAX, 2);
    }

    let cli = Cli::parse();

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    let workers = match &cli.command {
        Some(Commands::Run { workers, .. }) => *workers,
        _ => None,
    }
    .or_else(|| {
        std::env::var("FLUX_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
    });

    if let Some(w) = workers {
        builder.worker_threads(w);
    }
    builder.thread_stack_size(512 * 1024);

    let rt = builder.enable_all().build()?;

    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    let cmd = cli.command.unwrap_or(Commands::Version);

    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| match s.to_ascii_lowercase().as_str() {
            "trace" => Some(Level::TRACE),
            "debug" => Some(Level::DEBUG),
            "info" => Some(Level::INFO),
            "warn" => Some(Level::WARN),
            "error" => Some(Level::ERROR),
            _ => None,
        })
        .unwrap_or(Level::INFO);

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .compact()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    match cmd {
        Commands::Run {
            config,
            format,
            workers: _,
        } => {
            let fmt: ConfigFormat = format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;
            info!(
                "Starting flux-core with config: {:?} (format: {:?})",
                config, fmt
            );
            let cfg = load_any_config(&config, Some(fmt))?;
            let mut current_instance = Arc::new(Instance::new(cfg)?);
            current_instance.start().await?;

            info!(
                "flux-core started successfully. Press Ctrl+C to terminate, or send SIGHUP to hot-reload."
            );

            #[cfg(unix)]
            let mut sighup =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

            loop {
                #[cfg(unix)]
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received shutdown signal. Stopping flux-core...");
                        break;
                    }
                    _ = sighup.recv() => {
                        info!("Received SIGHUP! Reloading configuration from {:?}...", config);
                        match load_any_config(&config, Some(fmt)) {
                            Ok(new_cfg) => {
                                match Instance::new(new_cfg) {
                                    Ok(new_instance) => {
                                        let has_tun = new_instance.inbounds.iter().any(|i| i.protocol() == "tun")
                                            || current_instance.inbounds.iter().any(|i| i.protocol() == "tun");
                                        if has_tun {
                                            // TUN interface FD must be released before new instance can bind to tun0
                                            let _ = current_instance.stop().await;
                                        }
                                        if let Err(e) = new_instance.start().await {
                                            error!("Failed to start new instance during reload: {}", e);
                                            if has_tun {
                                                let _ = current_instance.start().await;
                                            }
                                        } else {
                                            let old = current_instance.clone();
                                            current_instance = Arc::new(new_instance);
                                            if !has_tun {
                                                tokio::spawn(async move {
                                                    let _ = old.stop().await;
                                                });
                                            }
                                            info!("Configuration hot-reloaded successfully!");
                                        }
                                    }
                                    Err(e) => error!("Failed to initialize new instance: {}", e),
                                }
                            }
                            Err(e) => error!("Failed to reload config from {:?}: {}", config, e),
                        }
                    }
                }

                #[cfg(not(unix))]
                {
                    tokio::signal::ctrl_c().await?;
                    break;
                }
            }

            info!("Shutting down flux-core...");
            current_instance.stop().await?;
            info!("Shutdown complete.");
        }
        Commands::Check { config, format } => {
            let fmt: ConfigFormat = format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;
            info!("Validating config: {:?} (format: {:?})", config, fmt);
            match load_any_config(&config, Some(fmt)) {
                Ok(cfg) => {
                    let _instance = Instance::new(cfg)?;
                    println!("Configuration is valid!");
                }
                Err(e) => {
                    eprintln!("Configuration check failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Trace {
            config,
            destination,
            network,
            inbound,
            format,
        } => {
            let fmt: ConfigFormat = format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;
            let cfg = load_any_config(&config, Some(fmt))?;
            let instance = Instance::new(cfg)?;

            let net = match network.to_ascii_lowercase().as_str() {
                "udp" => flux_types::NetworkType::Udp,
                _ => flux_types::NetworkType::Tcp,
            };
            let dst: flux_types::TargetAddress = destination
                .parse()
                .unwrap_or_else(|_| flux_types::TargetAddress::domain(&destination, 80));
            let dummy_src = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
            let meta = flux_types::SessionMeta::new(dummy_src, dst.clone(), inbound.as_str(), net);

            let (matched_outbound, active_node) = instance.trace_route(&meta);
            println!("=== flux-core Route Simulation ===");
            println!("Destination: {}", dst);
            println!("Network:     {}", net);
            println!("Inbound:     {}", inbound);
            println!("----------------------------------");
            println!("Matched Rule Outbound: [{}]", matched_outbound);
            println!("Active Exit Node:      [{}]", active_node);
            println!("==================================");
        }
        Commands::Version => {
            println!("flux-core v{}", env!("CARGO_PKG_VERSION"));
            println!(
                "Target: {}-{}",
                std::env::consts::ARCH,
                std::env::consts::OS
            );
            println!(
                "Configuration: Native Flux format (.json, .jsonc, .yaml, .yml) with modular $include"
            );
            println!(
                "Protocols: SOCKS5, HTTP CONNECT, VLESS (Reality & Vision), TROJAN, SHADOWSOCKS (AEAD & 2022), VMESS (AEAD), TUN, REDIRECT, TPROXY"
            );
            println!(
                "Carriers: TCP, TLS, QUIC, WebSocket, gRPC, H2, HTTPUpgrade, ShadowTLS v3, WireGuard/AmneziaWG, TUIC v5, Hysteria 2"
            );
            println!("Groups: Selector, UrlTest, Fallback, LoadBalance");
            println!("API: Flux Core Native API (/api/v1/*, Unix Socket, Route Tracer)");
        }
    }

    Ok(())
}
