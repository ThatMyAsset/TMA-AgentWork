use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tma_agent::model::{Request, Response};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "tma-doctor",
    about = "ThatMyAssets endpoint diagnostics and local queue administration"
)]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check service, pipe, worker, configuration and browser registration. No content is printed.
    Status,
    /// Send authenticated health request through production IPC.
    Health,
    /// Print metadata-only queue counts; never prints event bodies or inspected content.
    Queue,
    /// Attempt one heartbeat, policy sync and queue upload.
    Sync,
    /// Verify persistence and policy self-tests in the installed database.
    VerifyStore,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("tma-doctor: {error}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let data = cli.data_dir.unwrap_or_else(tma_agent::default_data_dir);
    let config = tma_agent::config::Config::load(&data.join("config.json"))?;
    match cli.command {
        Command::Status => {
            let diagnostics = tma_agent::platform::diagnostics(&config);
            println!("{}", serde_json::to_string_pretty(&diagnostics)?);
            if diagnostics.service.state != tma_agent::platform::ServiceState::Running
                || !diagnostics.ipc.credential_configured
            {
                std::process::exit(2)
            }
        }
        Command::Health => {
            let request = Request::Health {
                request_id: Uuid::new_v4(),
            };
            let response = ipc(&config, &request)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::Queue => {
            let stats = tma_agent::store::Store::open(&data.join("events.db"))?.stats()?;
            println!("{}", serde_json::to_string_pretty(&stats)?);
        }
        Command::Sync => {
            let agent = tma_agent::service::Agent::open(config, &data.join("events.db"))?;
            agent.sync_once();
            println!("synchronization attempted; inspect queue counts and service logs for transport status");
        }
        Command::VerifyStore => {
            let store = tma_agent::store::Store::open(&data.join("events.db"))?;
            let policy = store.policy()?;
            tma_agent::policy::validate(&policy)?;
            println!(
                "SQLite schema readable; policy {} valid; queue metadata intact",
                policy.version
            );
        }
    }
    Ok(())
}

#[cfg(windows)]
fn ipc(config: &tma_agent::config::Config, request: &Request) -> anyhow::Result<Response> {
    let mut pipe = tma_agent::platform::Pipe::client(std::time::Duration::from_secs(5))?;
    let body = serde_json::to_vec(request)?;
    let auth = tma_agent::protocol::request_authenticator(&config.ipc_credential, &body);
    let mut value = serde_json::to_value(request)?;
    value["auth"] = serde_json::Value::String(auth);
    tma_agent::protocol::write_frame(&mut pipe, &serde_json::to_vec(&value)?)?;
    let body = tma_agent::protocol::read_frame(&mut pipe)?
        .ok_or_else(|| anyhow::anyhow!("service closed connection"))?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(not(windows))]
fn ipc(_config: &tma_agent::config::Config, _request: &Request) -> anyhow::Result<Response> {
    anyhow::bail!("production named-pipe IPC is available only on Windows")
}
