use std::path::PathBuf;
use std::sync::Arc;
use clap::{Parser, Subcommand};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use flux_app::{Config, Instance};

#[derive(Parser)]
#[command(name = "flux-core")]
#[command(about = "High-performance proxy core in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the proxy core with a configuration file
    Run {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Validate configuration syntax and exit
    Check {
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },
    /// Print version information
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    match cli.command {
        Commands::Run { config } => {
            info!("Starting flux-core with config: {:?}", config);
            let content = tokio::fs::read_to_string(&config).await?;
            let cfg = Config::from_json_str(&content)?;
            let mut current_instance = Arc::new(Instance::new(cfg)?);
            current_instance.start().await?;

            info!("flux-core started successfully. Press Ctrl+C to terminate, or send SIGHUP to hot-reload.");

            #[cfg(unix)]
            let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

            loop {
                #[cfg(unix)]
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received shutdown signal. Stopping flux-core...");
                        break;
                    }
                    _ = sighup.recv() => {
                        info!("Received SIGHUP! Reloading configuration from {:?}...", config);
                        match tokio::fs::read_to_string(&config).await {
                            Ok(new_content) => {
                                match Config::from_json_str(&new_content) {
                                    Ok(new_cfg) => {
                                        match Instance::new(new_cfg) {
                                            Ok(new_instance) => {
                                                if let Err(e) = new_instance.start().await {
                                                    error!("Failed to start new instance during reload: {}", e);
                                                } else {
                                                    let old = current_instance.clone();
                                                    current_instance = Arc::new(new_instance);
                                                    tokio::spawn(async move {
                                                        let _ = old.stop().await;
                                                    });
                                                    info!("Configuration hot-reloaded successfully with 0 downtime!");
                                                }
                                            }
                                            Err(e) => error!("Failed to initialize new instance: {}", e),
                                        }
                                    }
                                    Err(e) => error!("Failed to parse reloaded config: {}", e),
                                }
                            }
                            Err(e) => error!("Failed to read config file during reload: {}", e),
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
        Commands::Check { config } => {
            info!("Validating config: {:?}", config);
            let content = tokio::fs::read_to_string(&config).await?;
            match Config::from_json_str(&content) {
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
        Commands::Version => {
            println!("flux-core v{}", env!("CARGO_PKG_VERSION"));
            println!("Target: x86_64-unknown-linux-gnu");
            println!("Protocols: SOCKS5, HTTP CONNECT, VLESS, REALITY, VISION, TROJAN, SHADOWSOCKS, TUN");
            println!("Features: Clash REST API, Fake-IP, Hot-Reload, Linux Zero-Copy Splice");
        }
    }

    Ok(())
}
