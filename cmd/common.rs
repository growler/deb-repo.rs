use {anyhow::Result, async_std::path::PathBuf};

#[async_trait::async_trait]
#[enum_dispatch::enum_dispatch]
pub trait AsyncCommand {
    async fn exec(&self, conf: &Config) -> Result<()>;
}

pub struct Config {
    pub manifest: PathBuf,
    pub quiet: bool,
    pub debug: u8,
    pub limit: usize,
    pub arch: String,
}
