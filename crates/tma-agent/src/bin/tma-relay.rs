use std::io::{self, Write};
use std::path::PathBuf;

fn main() {
    // Chrome reserves stdout for native messaging; never emit logs there.
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "tma-relay: {error}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let config_path = std::env::var_os("TMA_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\ThatMyAssets\config.json"));
    let config = tma_agent::config::Config::load(&config_path)?;
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    #[cfg(windows)]
    {
        let mut service = tma_agent::platform::Pipe::client(std::time::Duration::from_secs(5))?;
        return tma_agent::protocol::relay(
            &mut stdin,
            &mut stdout,
            &mut service,
            &config.ipc_credential,
        );
    }
    #[cfg(not(windows))]
    anyhow::bail!("native messaging relay requires the Windows service")
}
