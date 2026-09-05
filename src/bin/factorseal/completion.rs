//! Shell completion script generation.
//!
//! The generated scripts ask this executable for suggestions instead of
//! embedding them, so completion always matches the command definition of the
//! binary that answers it. Suggestions come from that definition alone: the
//! completion path never resolves a vault root, reads vault metadata, or
//! contacts the service.

use std::ffi::OsString;
use std::io;
use std::path::Path;

use clap::CommandFactory as _;
use clap_complete::env::{Bash, Elvish, EnvCompleter, Fish, Powershell, Shells, Zsh};

use super::cli::{Cli, CompletionShell};

const COMPLETE_VAR: &str = "FACTORSEAL_COMPLETE";
const BINARY: &str = "factorseal";

/// Answer a completion request and exit, or return when the shell is not
/// asking for one.
pub(super) fn complete() {
    let nushell = Nushell;
    let shells: [&dyn EnvCompleter; 6] = [&Bash, &Elvish, &Fish, &nushell, &Powershell, &Zsh];
    clap_complete::CompleteEnv::with_factory(Cli::command)
        .var(COMPLETE_VAR)
        .shells(Shells(&shells))
        .complete();
}

pub(super) fn generate(shell: CompletionShell, output: &mut dyn io::Write) -> io::Result<()> {
    match shell {
        CompletionShell::Bash => registration(&Bash, output),
        CompletionShell::Elvish => registration(&Elvish, output),
        CompletionShell::Fish => registration(&Fish, output),
        CompletionShell::Nushell => generate_nushell(output),
        CompletionShell::PowerShell => registration(&Powershell, output),
        CompletionShell::Zsh => registration(&Zsh, output),
    }
}

fn registration(shell: &dyn EnvCompleter, output: &mut dyn io::Write) -> io::Result<()> {
    shell.write_registration(COMPLETE_VAR, BINARY, BINARY, BINARY, output)
}

/// Nushell has no registration script. It loads a module whose declarations
/// delegate every value back to the same dynamic engine the other shells use.
///
/// Nushell resolves subcommand names from those declarations rather than from
/// the engine, so hidden commands are dropped here. The generator emits them
/// because it only filters hidden possible values.
fn generate_nushell(output: &mut dyn io::Write) -> io::Result<()> {
    let mut command = Cli::command();
    let hidden: Vec<String> = command
        .get_subcommands()
        .filter(|subcommand| subcommand.is_hide_set())
        .map(|subcommand| format!(" {}\"", subcommand.get_name()))
        .collect();
    let mut generated = Vec::new();
    clap_complete::generate(
        clap_complete_nushell::Nushell,
        &mut command,
        BINARY,
        &mut generated,
    );
    let generated = String::from_utf8(generated).map_err(io::Error::other)?;
    let completer = r#"module completions {

  def "nu-complete factorseal" [spans: list<string>] {
    with-env { FACTORSEAL_COMPLETE: nushell } {
      ^factorseal -- ...$spans
    } | from json
  }
"#;
    let generated = without_declarations(&generated, &hidden)
        .replacen("module completions {\n", completer, 1)
        .replace(
            "  export extern ",
            "  @complete 'nu-complete factorseal'\n  export extern ",
        );
    output.write_all(generated.as_bytes())
}

/// Drop every `export extern` declaration whose quoted command path ends with
/// one of `suffixes`. The generator separates declarations with a blank line
/// and never puts one inside a declaration.
fn without_declarations(module: &str, suffixes: &[String]) -> String {
    module
        .split("\n\n")
        .filter(|declaration| {
            let Some((path, _)) = declaration
                .split_once("export extern \"")
                .and_then(|(_, rest)| rest.split_once('['))
            else {
                return true;
            };
            !suffixes.iter().any(|suffix| path.contains(suffix.as_str()))
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

struct Nushell;

impl EnvCompleter for Nushell {
    fn name(&self) -> &'static str {
        "nushell"
    }

    fn is(&self, name: &str) -> bool {
        matches!(name, "nu" | "nushell")
    }

    fn write_registration(
        &self,
        _var: &str,
        _name: &str,
        _bin: &str,
        _completer: &str,
        _buf: &mut dyn io::Write,
    ) -> io::Result<()> {
        Err(io::Error::other(
            "Nushell registration is generated as a module",
        ))
    }

    fn write_complete(
        &self,
        command: &mut clap::Command,
        mut args: Vec<OsString>,
        current_dir: Option<&Path>,
        output: &mut dyn io::Write,
    ) -> io::Result<()> {
        if args.is_empty() {
            args.push(OsString::new());
        }
        let index = args.len() - 1;
        let completions = clap_complete::engine::complete(command, args, index, current_dir)?;
        let completions: Vec<_> = completions
            .into_iter()
            .map(|candidate| {
                serde_json::json!({
                    "value": candidate.get_value().to_string_lossy(),
                    "description": candidate.get_help().map(ToString::to_string).unwrap_or_default(),
                })
            })
            .collect();
        serde_json::to_writer(output, &completions).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::ValueEnum as _;

    const STATUS_HELP: &str = "Print validated non-secret vault metadata without unsealing";

    fn suggestions(typed: &str) -> Vec<clap_complete::CompletionCandidate> {
        let mut command = Cli::command();
        let args = vec![OsString::from(BINARY), OsString::from(typed)];
        let index = args.len() - 1;
        clap_complete::engine::complete(&mut command, args, index, None).unwrap()
    }

    #[test]
    fn every_shell_generates_a_script_that_asks_this_executable() {
        for shell in CompletionShell::value_variants() {
            let mut script = Vec::new();
            generate(*shell, &mut script).unwrap();
            let script = String::from_utf8(script).unwrap();

            assert!(script.contains(BINARY), "{shell:?} script omits the binary");
            assert!(
                script.contains(COMPLETE_VAR),
                "{shell:?} script omits the completion protocol"
            );
        }
    }

    #[test]
    fn suggestions_describe_commands_and_hide_the_internal_ones() {
        let candidates = suggestions("");
        let offered: Vec<_> = candidates
            .iter()
            .filter(|candidate| !candidate.is_hide_set())
            .map(|candidate| candidate.get_value().to_string_lossy().into_owned())
            .collect();

        assert!(offered.contains(&"status".to_owned()));
        assert!(offered.contains(&"completions".to_owned()));
        assert!(!offered.contains(&"desktop-worker".to_owned()));
        assert!(!offered.contains(&"sign-permission".to_owned()));

        let status = candidates
            .iter()
            .find(|candidate| candidate.get_value() == "status")
            .unwrap();
        assert_eq!(
            status.get_help().map(ToString::to_string).as_deref(),
            Some(STATUS_HELP)
        );
    }

    #[test]
    fn nushell_module_answers_the_same_engine_over_json() {
        let mut module = Vec::new();
        generate(CompletionShell::Nushell, &mut module).unwrap();
        let module = String::from_utf8(module).unwrap();
        assert!(module.contains("FACTORSEAL_COMPLETE: nushell"));
        assert!(module.contains("@complete 'nu-complete factorseal'"));
        assert!(module.contains("export extern factorseal ["));
        assert!(module.contains(r#"export extern "factorseal status""#));
        assert!(module.contains(r#"export extern "factorseal completions""#));
        assert!(!module.contains("desktop-worker"));
        assert!(!module.contains("sign-permission"));

        let mut command = Cli::command();
        let mut answered = Vec::new();
        Nushell
            .write_complete(
                &mut command,
                vec![OsString::from(BINARY), OsString::from("stat")],
                None,
                &mut answered,
            )
            .unwrap();
        let candidates: serde_json::Value = serde_json::from_slice(&answered).unwrap();
        let status = candidates
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["value"] == "status")
            .unwrap();
        assert_eq!(status["description"], STATUS_HELP);
    }
}
