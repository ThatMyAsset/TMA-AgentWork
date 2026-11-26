pub mod config;
pub mod control_plane;
pub mod detect;
pub mod inspect;
pub mod model;
pub mod platform;
pub mod policy;
pub mod protocol;
pub mod service;
pub mod store;
pub mod worker;

pub fn default_data_dir() -> std::path::PathBuf {
    std::env::var_os("TMA_DATA_DIR")
        .map(Into::into)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData\ThatMyAssets"))
}
