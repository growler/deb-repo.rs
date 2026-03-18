use {
    crate::{
        artifact::FileModeArgParser,
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
        io::Write,
        num::NonZero,
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
/// CLI command that edits manifests or spec metadata.
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
    Artifact(EditArtifact),
}

#[derive(Parser)]
#[command(about = "Edit build environment variables for a spec")]
struct EditEnv;

#[derive(Parser)]
#[command(about = "Edit build script for a spec")]
struct EditScript;

#[derive(Parser)]
#[command(about = "Edit inline text artifact content")]
struct EditArtifact {
    /// Artifact name
    #[arg(value_name = "NAME")]
    name: String,

    /// Target path inside the staging filesystem
    #[arg(long = "target", value_name = "TARGET_PATH")]
    target: String,

    /// Target file mode in octal, e.g. 0644 or 0755
    #[arg(long = "mode", value_name = "MODE", value_parser = FileModeArgParser)]
    mode: Option<NonZero<u32>>,

    /// Target architecture for the artifact
    #[arg(long = "only-arch", value_name = "ARCH")]
    target_arch: Option<String>,

    /// Stage the artifact into a spec (default spec if --spec is omitted)
    #[arg(long = "stage", action)]
    stage: bool,
}

impl<C: Config> Command<C> for Edit {
    fn exec(&self, conf: &C) -> Result<()> {
        let editor = EditorCommand::resolve(self.opts.edit.as_deref())?;
        let cmd = self.cmd.as_ref();
        let spec = self.opts.spec.as_deref();
        smol::block_on(async move {
            if cmd.is_none() {
                // edit manifest is the only command that can work with
                // stale/unlocked manifest
                return edit_manifest(conf, &editor).await;
            }
            let cmd = cmd.unwrap();
            let (mut manifest, has_valid_lock) =
                Manifest::from_file(conf.manifest(), conf.arch()).await?;
            if !has_valid_lock {
                return Err(anyhow!("manifest lock is not live; run update first"));
            }
            match cmd {
                EditCommands::Env(_) => edit_env(&mut manifest, &editor, spec).await?,
                EditCommands::Script(_) => edit_script(&mut manifest, &editor, spec).await?,
                EditCommands::Artifact(artifact) => {
                    edit_artifact(&mut manifest, &editor, spec, artifact).await?;
                }
            }
            let fetcher = conf.fetcher()?;
            let guard = fetcher.init().await?;
            manifest.resolve(conf.concurrency(), fetcher).await?;
            manifest.store().await?;
            guard.commit().await?;
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
            .or_else(|| {
                std::fs::metadata("/usr/bin/edit")
                    .map(|md| md.is_file())
                    .is_ok()
                    .then(|| "/usr/bin/edit".to_string())
            })
            .ok_or_else(|| anyhow!("editor not configured and /usr/bin/edit is absent: set $VISUAL/$EDITOR or pass --edit"))?;
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

async fn edit_manifest<C: Config>(conf: &C, editor: &EditorCommand) -> Result<()> {
    let path = smol::fs::canonicalize(conf.manifest()).await?;
    editor.run(&path)?;
    let (mut mf, has_valid_lock) = Manifest::from_file(conf.manifest(), conf.arch())
        .await
        .map_err(|err| {
            anyhow!("failed to load manifest after editing: {err}; manifest may be malformed",)
        })?;
    if has_valid_lock {
        // nothing changed
        return Ok(());
    }
    let fetcher = conf.fetcher()?;
    let guard = fetcher.init().await?;
    mf.resolve(conf.concurrency(), fetcher)
        .await
        .map_err(|err| {
            anyhow!("failed to resolve manifest after editing: {err}; manifest may be malformed",)
        })?;
    mf.store().await.map_err(|err| {
        anyhow!("failed to store manifest after editing: {err}; manifest may be malformed",)
    })?;
    guard.commit().await?;
    Ok(())
}

async fn edit_env(
    manifest: &mut Manifest,
    editor: &EditorCommand,
    spec: Option<&str>,
) -> Result<()> {
    let env = manifest.spec_build_env(spec)?;
    let comments = manifest.spec_build_env_comments(spec)?;
    let mut tmp = tempfile::Builder::new().suffix(".env").tempfile()?;
    write_env_file(&mut tmp, &env, &comments)?;
    editor.run(tmp.path())?;
    let contents = std::fs::read_to_string(tmp.path())?;
    let parsed = parse_env_file(&contents)?;
    manifest.set_build_env_with_comments(spec, parsed.env, parsed.comments)?;
    Ok(())
}

async fn edit_script(
    manifest: &mut Manifest,
    editor: &EditorCommand,
    spec: Option<&str>,
) -> Result<()> {
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
    Ok(())
}

async fn edit_artifact(
    manifest: &mut Manifest,
    editor: &EditorCommand,
    spec: Option<&str>,
    artifact: &EditArtifact,
) -> Result<()> {
    let mut existing_text = None;
    let mut existing_mode = None;
    let mut existing_arch = None;
    if let Some(existing) = manifest.artifact(&artifact.name) {
        let existing = existing
            .as_text()
            .ok_or_else(|| anyhow!("artifact {} exists but is not text", artifact.name.as_str()))?;
        existing_text = Some(existing.text().to_string());
        existing_mode = existing.mode();
        existing_arch = existing.arch().map(str::to_string);
    }
    let mut tmp = tempfile::Builder::new().suffix(".txt").tempfile()?;
    if let Some(text) = existing_text {
        write!(tmp, "{text}")?;
    }
    tmp.flush()?;
    editor.run(tmp.path())?;
    let contents = std::fs::read_to_string(tmp.path())?;
    let mode = artifact.mode.or(existing_mode);
    let arch = artifact.target_arch.clone().or(existing_arch);
    manifest.upsert_text_artifact(
        &artifact.name,
        artifact.target.clone(),
        contents,
        mode,
        arch,
    )?;
    if artifact.stage {
        manifest.add_stage_items(spec, vec![artifact.name.clone()], None)?;
    }
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
            if pos > 0 && value_part[..pos].chars().last().map(|c| c.is_whitespace()) == Some(true)
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
