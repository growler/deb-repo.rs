use {
    crate::{
        cli::{Command, Config},
        content::{ContentProvider, ContentProviderGuard},
        kvlist::KVList,
        manifest::Manifest,
        manifest_doc::BuildEnvComments,
    },
    anyhow::{anyhow, Result},
    clap::{Args, Parser},
    std::{
        collections::HashSet,
        env,
        io::{self, Write},
        path::Path,
        process::{Command as ProcessCommand, Stdio},
    },
};

#[derive(Args, Clone)]
struct EditOptions {
    /// Target spec (omit to use the default spec)
    #[arg(short = 's', long = "spec", value_name = "SPEC", global = true)]
    spec: Option<String>,

    /// Editor command to use (defaults to $VISUAL or $EDITOR)
    #[arg(long = "edit", value_name = "EDITOR", global = true)]
    edit: Option<String>,
}

#[derive(Parser)]
#[command(about = "Edit the manifest or spec metadata")]
pub struct Edit {
    #[command(flatten)]
    opts: EditOptions,

    #[command(subcommand)]
    cmd: Option<EditCommands>,
}

#[derive(Parser)]
enum EditCommands {
    Env(EditEnv),
    Script(EditScript),
}

#[derive(Parser)]
#[command(about = "Edit build environment variables for a spec")]
struct EditEnv;

#[derive(Parser)]
#[command(about = "Edit build script for a spec")]
struct EditScript;

impl<C: Config> Command<C> for Edit {
    fn exec(&self, conf: &C) -> Result<()> {
        let editor = EditorCommand::resolve(self.opts.edit.as_deref())?;
        let cmd = self.cmd.as_ref();
        let spec = self.opts.spec.as_deref();
        smol::block_on(async move {
            let manifest_path = conf.manifest().to_path_buf();
            let lock_path = manifest_path.with_extension(format!("{}.lock", conf.arch()));
            let manifest_backup = smol::fs::read(&manifest_path).await?;
            let lock_backup = match smol::fs::read(&lock_path).await {
                Ok(bytes) => Some(bytes),
                Err(err) if err.kind() == io::ErrorKind::NotFound => None,
                Err(err) => return Err(err.into()),
            };

            match cmd {
                None => editor.run(&manifest_path)?,
                Some(EditCommands::Env(_)) => edit_env(conf, &editor, spec).await?,
                Some(EditCommands::Script(_)) => edit_script(conf, &editor, spec).await?,
            }

            if let Err(err) = run_update(conf).await {
                let rollback = rollback_files(
                    &manifest_path,
                    &manifest_backup,
                    &lock_path,
                    lock_backup.as_deref(),
                )
                .await;
                if let Err(rollback_err) = rollback {
                    return Err(anyhow!("update failed: {err}; rollback failed: {rollback_err}"));
                }
                return Err(err);
            }

            Ok(())
        })
    }
}

struct EditorCommand {
    program: String,
    args: Vec<String>,
}

impl EditorCommand {
    fn resolve(edit: Option<&str>) -> Result<Self> {
        let editor = edit
            .map(|value| value.to_string())
            .or_else(|| env::var("VISUAL").ok())
            .or_else(|| env::var("EDITOR").ok())
            .ok_or_else(|| anyhow!("editor not configured: set $VISUAL/$EDITOR or pass --edit"))?;
        let mut parts = editor.split_whitespace();
        let program = parts
            .next()
            .ok_or_else(|| anyhow!("editor command is empty"))?
            .to_string();
        let args = parts.map(|part| part.to_string()).collect::<Vec<_>>();
        Ok(Self { program, args })
    }

    fn run(&self, path: &Path) -> Result<()> {
        let status = ProcessCommand::new(&self.program)
            .args(&self.args)
            .arg(path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()?;
        if !status.success() {
            return Err(anyhow!("editor exited with status {status}"));
        }
        Ok(())
    }
}

async fn edit_env<C: Config>(
    conf: &C,
    editor: &EditorCommand,
    spec: Option<&str>,
) -> Result<()> {
    let mut manifest = Manifest::from_file(conf.manifest(), conf.arch()).await?;
    let env = manifest.spec_build_env(spec)?;
    let comments = manifest.spec_build_env_comments(spec)?;
    let mut tmp = tempfile::Builder::new().suffix(".env").tempfile()?;
    write_env_file(&mut tmp, &env, &comments)?;
    editor.run(tmp.path())?;
    let contents = std::fs::read_to_string(tmp.path())?;
    let parsed = parse_env_file(&contents)?;
    manifest.set_build_env_with_comments(spec, parsed.env, parsed.comments)?;
    manifest.store_manifest_only(conf.manifest()).await?;
    Ok(())
}

async fn edit_script<C: Config>(
    conf: &C,
    editor: &EditorCommand,
    spec: Option<&str>,
) -> Result<()> {
    let mut manifest = Manifest::from_file(conf.manifest(), conf.arch()).await?;
    let script = manifest.spec_build_script(spec)?;
    let mut tmp = tempfile::Builder::new().suffix(".sh").tempfile()?;
    if let Some(script) = script {
        write!(tmp, "{script}")?;
    }
    tmp.flush()?;
    editor.run(tmp.path())?;
    let contents = std::fs::read_to_string(tmp.path())?;
    let script = if contents.trim().is_empty() {
        None
    } else {
        Some(contents)
    };
    manifest.set_build_script(spec, script)?;
    manifest.store_manifest_only(conf.manifest()).await?;
    Ok(())
}

fn write_env_file(
    file: &mut tempfile::NamedTempFile,
    env: &KVList<String>,
    comments: &BuildEnvComments,
) -> Result<()> {
    for (key, value) in env.iter() {
        if let Some(prefix) = comments.prefix.get(key) {
            if !prefix.is_empty() {
                write!(file, "{prefix}")?;
                if !prefix.ends_with('\n') {
                    writeln!(file)?;
                }
            }
        }
        write!(file, "{key}={value}")?;
        if let Some(inline) = comments.inline.get(key) {
            if !inline.is_empty() {
                if inline.chars().next().map(|c| c.is_whitespace()) == Some(true) {
                    write!(file, "{inline}")?;
                } else {
                    write!(file, " {inline}")?;
                }
            }
        }
        writeln!(file)?;
    }
    file.flush()?;
    Ok(())
}

struct ParsedEnv {
    env: KVList<String>,
    comments: BuildEnvComments,
}

fn parse_env_file(contents: &str) -> Result<ParsedEnv> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    let mut comments = BuildEnvComments::default();
    let mut pending = String::new();
    for (idx, raw_line) in contents.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            pending.push('\n');
            continue;
        }
        if raw_line.trim_start().starts_with('#') {
            pending.push_str(raw_line.trim_end());
            pending.push('\n');
            continue;
        }
        let (key, value_part) = raw_line.split_once('=').ok_or_else(|| {
            anyhow!(
                "invalid env line {}: expected VAR=value",
                idx.saturating_add(1)
            )
        })?;
        let key = key.trim();
        if key.is_empty() {
            return Err(anyhow!("invalid env line {}: empty key", idx + 1));
        }
        if !seen.insert(key.to_string()) {
            return Err(anyhow!("duplicate env key '{}'", key));
        }
        let mut value = value_part.trim_end();
        let mut inline = String::new();
        if let Some(pos) = value_part.find('#') {
            if pos > 0
                && value_part[..pos]
                    .chars()
                    .last()
                    .map(|c| c.is_whitespace())
                    == Some(true)
            {
                let before = &value_part[..pos];
                let spacing_start = before
                    .rfind(|c: char| !c.is_whitespace())
                    .map(|idx| idx + 1)
                    .unwrap_or(0);
                let spacing = &before[spacing_start..];
                inline.push_str(spacing);
                inline.push_str(value_part[pos..].trim_end());
                value = value_part[..spacing_start].trim_end();
            }
        }
        let prefix = pending.clone();
        pending.clear();
        items.push((key.to_string(), value.trim().to_string()));
        comments.prefix.insert(key.to_string(), prefix);
        comments.inline.insert(key.to_string(), inline);
    }
    Ok(ParsedEnv {
        env: KVList::from(items),
        comments,
    })
}

async fn run_update<C: Config>(conf: &C) -> Result<()> {
    let fetcher = conf.fetcher()?;
    let guard = fetcher.init().await?;
    let mut manifest = Manifest::from_file(conf.manifest(), conf.arch()).await?;
    manifest
        .update(false, false, conf.concurrency(), fetcher)
        .await?;
    manifest.store(conf.manifest()).await?;
    guard.commit().await?;
    Ok(())
}

async fn rollback_files(
    manifest_path: &Path,
    manifest_backup: &[u8],
    lock_path: &Path,
    lock_backup: Option<&[u8]>,
) -> Result<()> {
    crate::safe_store(
        manifest_path,
        smol::io::Cursor::new(manifest_backup.to_vec()),
    )
    .await?;
    match lock_backup {
        Some(bytes) => {
            crate::safe_store(lock_path, smol::io::Cursor::new(bytes.to_vec())).await?;
        }
        None => match smol::fs::remove_file(lock_path).await {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        },
    }
    Ok(())
}
