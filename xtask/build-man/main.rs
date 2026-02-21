use clap::{Arg, ArgAction, ColorChoice, Command, CommandFactory};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

fn main() -> anyhow::Result<()> {
    let target_dir = PathBuf::from("target/man");
    fs::create_dir_all(&target_dir)?;

    let mut cmd = rdebootstrap::App::command()
        .bin_name("rdebootstrap")
        .color(ColorChoice::Never);

    let mut output = String::new();
    render_single_page(&mut cmd, &mut output)?;
    let out_path = target_dir.join("rdebootstrap.1");
    fs::write(&out_path, output)?;

    println!("Man page generated in {}", out_path.display());

    Ok(())
}

fn render_single_page(cmd: &mut Command, out: &mut String) -> std::io::Result<()> {
    let name = cmd.get_name().to_string();
    let about = cmd
        .get_about()
        .map(|about| about.to_string())
        .unwrap_or_default();
    let long_about = cmd
        .get_long_about()
        .map(|about| about.to_string())
        .unwrap_or_else(|| about.clone());

    out.push_str(".TH \"");
    out.push_str(&escape_roff_inline(&name));
    out.push_str("\" \"1\" \"\" \"");
    out.push_str(&escape_roff_inline(&name));
    out.push_str("\" \"User Commands\"\n");

    render_name_section(out, &name, &about);
    render_synopsis_section(out, &name);
    render_description_section(out, &long_about);
    render_options_section(out, cmd);
    render_commands_section(out, cmd);
    render_command_details(out, &name, cmd);

    append_section_files(
        out,
        &[
            "docs/man/examples.roff",
            "docs/man/files.roff",
            "docs/man/environment.roff",
            "docs/man/see-also.roff",
        ],
    )?;

    Ok(())
}

fn render_name_section(out: &mut String, name: &str, about: &str) {
    if about.trim().is_empty() {
        return;
    }
    out.push_str(".SH NAME\n");
    out.push_str(&escape_roff(&format!("{name} - {about}")));
    out.push('\n');
}

fn render_synopsis_section(out: &mut String, name: &str) {
    out.push_str(".SH SYNOPSIS\n");
    out.push_str("\\fB");
    out.push_str(&escape_roff_inline(name));
    out.push_str(
        "\\fR [\\fIglobal-options\\fR] \\fIcommand\\fR [\\fIcommand-options\\fR] [\\fIargs...\\fR]\n",
    );
    out.push_str(".PP\n");
    out.push_str("\\fB");
    out.push_str(&escape_roff_inline(name));
    out.push_str("\\fR \\fIcommand\\fR \\fB--help\\fR\n");
}

fn render_description_section(out: &mut String, text: &str) {
    if text.trim().is_empty() {
        return;
    }
    out.push_str(".SH DESCRIPTION\n");
    push_text_block(out, text);
}

fn render_options_section(out: &mut String, cmd: &Command) {
    let args: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|arg| !arg.is_positional() && !arg.is_hide_set())
        .collect();
    if args.is_empty() {
        return;
    }
    out.push_str(".SH OPTIONS\n");
    out.push_str("Global options (must be specified before the subcommand):\n");
    for arg in args {
        let label = format_option_label(arg);
        let desc = format_arg_description(arg);
        push_term(out, &label, &desc);
    }
}

fn render_commands_section(out: &mut String, cmd: &Command) {
    let mut entries = Vec::new();
    collect_command_entries(cmd, &mut Vec::new(), &mut entries);
    if entries.is_empty() {
        return;
    }
    out.push_str(".SH COMMANDS\n");
    for entry in entries {
        push_term(out, &entry.label, &entry.description);
    }
    out.push_str("Run \\fBrdebootstrap <command> --help\\fR for command-specific options.\n");
}

fn render_command_details(out: &mut String, root: &str, cmd: &Command) {
    let global_ids = collect_global_arg_ids(cmd);
    for sub in cmd.get_subcommands() {
        if should_skip_command(sub) {
            continue;
        }
        let section_title = sub.get_name().to_string();
        let full_path = format!("{root} {}", sub.get_name());
        render_command_section(out, root, &section_title, &full_path, sub, &global_ids);
    }
}

fn render_command_section(
    out: &mut String,
    root: &str,
    section_title: &str,
    full_path: &str,
    cmd: &Command,
    global_ids: &HashSet<String>,
) {
    let about = cmd
        .get_about()
        .map(|about| about.to_string())
        .unwrap_or_default();
    let long_about = cmd
        .get_long_about()
        .map(|about| about.to_string())
        .unwrap_or_else(|| about.clone());

    out.push_str(".SS ");
    out.push_str(&escape_roff_inline(section_title));
    out.push('\n');

    if !long_about.trim().is_empty() {
        push_text_block(out, &long_about);
    }

    let usage = {
        let mut cloned = cmd.clone().color(ColorChoice::Never);
        format_usage_line(root, full_path, &mut cloned)
    };
    out.push_str(".PP\nSYNOPSIS:\n.PP\n.nf\n");
    out.push_str(&escape_roff(&usage));
    out.push_str("\n.fi\n");

    let args = collect_positional_args(cmd);
    if !args.is_empty() {
        out.push_str(".PP\nArguments:\n");
        for arg in args {
            let label = format_positional_label(arg);
            let desc = format_arg_description(arg);
            push_term(out, &label, &desc);
        }
    }

    let options = cmd
        .get_arguments()
        .filter(|arg| {
            !arg.is_positional()
                && !arg.is_hide_set()
                && !global_ids.contains(arg.get_id().as_str())
                && !is_builtin_help(arg)
        })
        .collect::<Vec<_>>();
    if !options.is_empty() {
        out.push_str(".PP\nOptions:\n");
        for arg in options {
            let label = format_option_label(arg);
            let desc = format_arg_description(arg);
            push_term(out, &label, &desc);
        }
    }

    let subcommands = cmd
        .get_subcommands()
        .filter(|sub| !should_skip_command(sub))
        .collect::<Vec<_>>();
    if !subcommands.is_empty() {
        out.push_str(".PP\nSubcommands:\n");
        for sub in subcommands.iter() {
            let label = format_command_label(sub.get_name(), None);
            let desc = command_description(sub);
            push_term(out, &label, &desc);
        }
    }

    for sub in subcommands {
        let new_section = format!("{section_title} {}", sub.get_name());
        let new_full = format!("{full_path} {}", sub.get_name());
        render_command_section(out, root, &new_section, &new_full, sub, global_ids);
    }
}

fn collect_command_entries(cmd: &Command, prefix: &mut Vec<String>, out: &mut Vec<CommandEntry>) {
    for sub in cmd.get_subcommands() {
        if should_skip_command(sub) {
            continue;
        }
        prefix.push(sub.get_name().to_string());
        if sub.get_subcommands().next().is_some() {
            collect_command_entries(sub, prefix, out);
        } else {
            let args = format_positional_summary(sub);
            let label = format_command_label(&prefix.join(" "), Some(&args));
            let description = command_description(sub);
            out.push(CommandEntry { label, description });
        }
        prefix.pop();
    }
}

fn format_usage_line(root: &str, full_path: &str, cmd: &mut Command) -> String {
    let usage = cmd.render_usage().to_string();
    let usage_line = usage.lines().next().unwrap_or("").trim();
    let usage_line = usage_line
        .strip_prefix("Usage: ")
        .unwrap_or(usage_line)
        .trim();
    if usage_line.starts_with(root) {
        usage_line.to_string()
    } else if let Some(rest) = usage_line.strip_prefix(cmd.get_name()) {
        format!("{full_path}{rest}")
    } else {
        format!("{full_path} {usage_line}")
    }
}

fn format_command_label(command: &str, args: Option<&str>) -> String {
    let mut label = String::new();
    label.push_str("\\fB");
    label.push_str(&escape_roff_inline(command));
    label.push_str("\\fR");
    if let Some(args) = args {
        if !args.trim().is_empty() {
            label.push(' ');
            label.push_str("\\fI");
            label.push_str(&escape_roff_inline(args));
            label.push_str("\\fR");
        }
    }
    label
}

fn format_positional_summary(cmd: &Command) -> String {
    let args = collect_positional_args(cmd);
    let mut parts = Vec::new();
    for arg in args {
        parts.push(format_positional_name(arg, true));
    }
    parts.join(" ")
}

fn collect_positional_args(cmd: &Command) -> Vec<&Arg> {
    cmd.get_arguments()
        .filter(|arg| arg.is_positional() && !arg.is_hide_set())
        .collect()
}

fn format_positional_label(arg: &Arg) -> String {
    let name = format_positional_name(arg, false);
    format!("\\fI{}\\fR", escape_roff_inline(&name))
}

fn format_positional_name(arg: &Arg, bracket_optional: bool) -> String {
    let base = arg
        .get_value_names()
        .and_then(|names| names.first().map(|name| name.as_str().to_string()))
        .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
    let mut name = base;
    if is_multi_valued(arg) {
        name.push_str("...");
    }
    if bracket_optional && !arg.is_required_set() {
        format!("[{name}]")
    } else {
        name
    }
}

fn format_option_label(arg: &Arg) -> String {
    let mut parts = Vec::new();
    if let Some(short) = arg.get_short() {
        parts.push(format!("\\fB{}\\fR", escape_option(&format!("-{short}"))));
    }
    if let Some(long) = arg.get_long() {
        parts.push(format!("\\fB{}\\fR", escape_option(&format!("--{long}"))));
    }
    let mut label = parts.join(", ");
    if arg_takes_value(arg) {
        let value = format_value_name(arg);
        if !value.is_empty() {
            label.push(' ');
            label.push_str("\\fI");
            label.push_str(&escape_roff_inline(&value));
            label.push_str("\\fR");
        }
    }
    label
}

fn format_value_name(arg: &Arg) -> String {
    if let Some(names) = arg.get_value_names() {
        let values = names
            .iter()
            .map(|name| name.as_str().to_string())
            .collect::<Vec<_>>();
        return values.join(" ");
    }
    arg.get_id().as_str().to_uppercase()
}

fn format_arg_description(arg: &Arg) -> String {
    let mut desc = arg
        .get_long_help()
        .or_else(|| arg.get_help())
        .map(|help| help.to_string())
        .unwrap_or_default();
    let default_vals = arg.get_default_values();
    if !default_vals.is_empty() {
        let defaults = default_vals
            .iter()
            .filter_map(|val| val.to_str())
            .collect::<Vec<_>>()
            .join(", ");
        append_sentence(&mut desc, &format!("Default: {defaults}."));
    }
    if arg_takes_value(arg) {
        let possible_values = arg
            .get_possible_values()
            .into_iter()
            .filter(|pv| !pv.is_hide_set())
            .map(|pv| pv.get_name().to_string())
            .collect::<Vec<_>>();
        if !possible_values.is_empty() {
            append_sentence(
                &mut desc,
                &format!("Possible values: {}.", possible_values.join(", ")),
            );
        }
    }
    if let Some(env) = arg.get_env().and_then(|env| env.to_str()) {
        append_sentence(&mut desc, &format!("Env: {env}."));
    }
    desc
}

fn append_sentence(text: &mut String, sentence: &str) {
    if text.trim().is_empty() {
        text.push_str(sentence);
        return;
    }
    if !text.trim_end().ends_with(['.', '!', '?']) {
        text.push('.');
    }
    text.push(' ');
    text.push_str(sentence);
}

fn command_description(cmd: &Command) -> String {
    let desc = cmd
        .get_about()
        .or_else(|| cmd.get_long_about())
        .map(|about| about.to_string())
        .unwrap_or_default();
    desc.lines().next().unwrap_or("").trim().to_string()
}

fn should_skip_command(cmd: &Command) -> bool {
    cmd.is_hide_set() || cmd.get_name() == "help"
}

fn collect_global_arg_ids(cmd: &Command) -> HashSet<String> {
    cmd.get_arguments()
        .filter(|arg| arg.is_global_set())
        .map(|arg| arg.get_id().as_str().to_string())
        .collect()
}

fn is_builtin_help(arg: &Arg) -> bool {
    matches!(arg.get_id().as_str(), "help" | "version")
}

fn arg_takes_value(arg: &Arg) -> bool {
    match arg.get_action() {
        ArgAction::Set | ArgAction::Append => true,
        ArgAction::SetTrue
        | ArgAction::SetFalse
        | ArgAction::Count
        | ArgAction::Help
        | ArgAction::Version => false,
        _ => arg
            .get_num_args()
            .map(|range| range.takes_values())
            .unwrap_or(false),
    }
}

fn is_multi_valued(arg: &Arg) -> bool {
    arg.get_num_args()
        .map(|range| range.max_values() > 1)
        .unwrap_or(false)
}

fn push_term(out: &mut String, term: &str, desc: &str) {
    out.push_str(".TP\n");
    out.push_str(term);
    out.push('\n');
    out.push_str(&escape_roff(desc));
    out.push('\n');
}

fn push_text_block(out: &mut String, text: &str) {
    let paragraphs = text.split("\n\n");
    for (idx, para) in paragraphs.enumerate() {
        if idx > 0 {
            out.push_str(".PP\n");
        }
        let use_pre = para.lines().any(|line| line.starts_with([' ', '\t']));
        if use_pre {
            out.push_str(".nf\n");
            out.push_str(&escape_roff(para.trim_end()));
            out.push_str("\n.fi\n");
        } else {
            out.push_str(&escape_roff(para.trim_end()));
            out.push('\n');
        }
    }
}

fn append_section_files(out: &mut String, files: &[&str]) -> std::io::Result<()> {
    for file in files {
        let path = Path::new(file);
        if !path.exists() {
            continue;
        }
        let content = fs::read_to_string(path)?;
        if !content.is_empty() {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&content);
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    Ok(())
}

fn escape_roff(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (idx, line) in text.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        if line.starts_with('.') || line.starts_with('\'') {
            out.push_str("\\&");
        }
        for ch in line.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                _ => out.push(ch),
            }
        }
    }
    out
}

fn escape_roff_inline(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out
}

fn escape_option(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 4);
    for (idx, ch) in text.chars().enumerate() {
        if idx == 0 && ch == '-' {
            out.push_str("\\-");
            continue;
        }
        if idx == 1 && text.starts_with("--") && ch == '-' {
            out.push_str("\\-");
            continue;
        }
        match ch {
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out
}

struct CommandEntry {
    label: String,
    description: String,
}
