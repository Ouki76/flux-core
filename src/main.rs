use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, Level};
use flux_app::{Config, Instance};

enum Commands {
    Run { config: PathBuf },
    Check { config: PathBuf },
    Version,
}

fn parse_args() -> Result<Commands, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return Ok(Commands::Version);
    }
    match args[0].as_str() {
        "run" => {
            let mut cfg_path = None;
            let mut i = 1;
            while i < args.len() {
                if (args[i] == "-c" || args[i] == "--config") && i + 1 < args.len() {
                    cfg_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let config = cfg_path.ok_or_else(|| "missing --config / -c argument".to_string())?;
            Ok(Commands::Run { config })
        }
        "check" => {
            let mut cfg_path = None;
            let mut i = 1;
            while i < args.len() {
                if (args[i] == "-c" || args[i] == "--config") && i + 1 < args.len() {
                    cfg_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let config = cfg_path.ok_or_else(|| "missing --config / -c argument".to_string())?;
            Ok(Commands::Check { config })
        }
        "version" | "-v" | "--version" => Ok(Commands::Version),
        other => Err(format!("unknown command: {}", other)),
    }
}

fn main() -> anyhow::Result<()> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Ok(workers_str) = std::env::var("FLUX_WORKERS") {
        if let Ok(w) = workers_str.parse::<usize>() {
            builder.worker_threads(w);
        }
    }
    let rt = builder.enable_all().build()?;

    rt.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    let cmd = parse_args().unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        eprintln!("Usage: flux-core [run|check] -c <config.json>");
        std::process::exit(1);
    });

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
