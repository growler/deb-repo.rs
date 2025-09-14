use {
    crate::version::{Constraint, Dependency, Version},
    std::str::FromStr,
};
pub use {
    crate::source::{Source, Vendor},
};

/// A parser type for converting command-line argument strings into a `Dependency`.
///
/// Example:
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Args {
///     #[arg(value_parser = DependencyParser)]
///     dependency: Vec<Dependency>,
/// }
/// ```
#[derive(Clone)]
pub struct DependencyParser;

impl clap::builder::TypedValueParser for DependencyParser {
    type Value = Dependency<String>;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;
        Self::Value::from_str(value).map_err(|e| {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String(format!("{}", e)),
            );
            err
        })
    }
}

/// A parser type for converting command-line argument strings into a `Constraint`.
///
/// Example:
/// ```ignore
/// #[derive(clap::Parser)]
/// struct Args {
///     #[arg(value_parser = ConstraintParser)]
///     dependency: Vec<Constraint>,
/// }
/// ```
#[derive(Clone)]
pub struct ConstraintParser;

impl clap::builder::TypedValueParser for ConstraintParser {
    type Value = Constraint<String>;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value.to_str().ok_or_else(|| {
            let mut err = clap::Error::new(clap::error::ErrorKind::InvalidUtf8).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err
        })?;
        Self::Value::from_str(value).map_err(|e| {
            let mut err = clap::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            if let Some(arg) = arg {
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg.to_string()),
                );
            }
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(value.to_string()),
            );
            err.insert(
                clap::error::ContextKind::Custom,
                clap::error::ContextValue::String(format!("{}", e)),
            );
            err
        })
    }
}

