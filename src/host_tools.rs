//! Running host system tools (`ldconfig`, `dpkg-query`, `rpm`) safely as root.
//!
//! rgwtrace runs as root. Resolving a tool through the caller's `PATH` lets
//! whoever controls that `PATH` (or any writable directory early in it) run code
//! as root, so these tools are invoked only by absolute path, with a cleared
//! environment and a fixed system `PATH` for anything they exec in turn.

use std::{path::Path, process::Command};

/// `PATH` handed to a host tool: system directories only.
const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

pub const LDCONFIG: &[&str] = &["/sbin/ldconfig", "/usr/sbin/ldconfig"];
pub const DPKG_QUERY: &[&str] = &["/usr/bin/dpkg-query"];
pub const RPM: &[&str] = &["/usr/bin/rpm", "/bin/rpm"];

/// A `Command` for the first of `candidates` (absolute paths) that exists, with
/// a cleared environment. `None` when the tool is not installed.
pub fn system_command(candidates: &[&str]) -> Option<Command> {
    let program = candidates
        .iter()
        .find(|candidate| Path::new(candidate).is_absolute() && Path::new(candidate).is_file())?;
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("LC_ALL", "C");
    Some(command)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn missing_tool_yields_no_command() {
        assert!(system_command(&["/nonexistent/rgwtrace-tool"]).is_none());
    }

    #[test]
    fn relative_candidates_are_never_resolved() {
        // A bare name would be looked up through PATH -- exactly what this
        // module exists to prevent.
        assert!(system_command(&["sh"]).is_none());
    }

    #[test]
    fn command_uses_the_absolute_path_and_a_fixed_environment() {
        let command = system_command(&["/nonexistent/sh", "/bin/sh"]).unwrap();

        assert_eq!(command.get_program(), OsStr::new("/bin/sh"));
        let envs: Vec<_> = command.get_envs().collect();
        assert!(envs.contains(&(OsStr::new("PATH"), Some(OsStr::new(SYSTEM_PATH)))));
    }
}
