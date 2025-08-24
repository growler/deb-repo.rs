use {anyhow::Result, async_std::path::PathBuf};

#[async_trait::async_trait(?Send)]
#[enum_dispatch::enum_dispatch]
pub trait AsyncCommand {
    async fn exec(&self, conf: &Config) -> Result<()>;
}

pub struct Config {
    pub manifest: PathBuf,
    pub limit: usize,
    pub arch: String,
}
