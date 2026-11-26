//! Re-execution of the running process for `POST /api/system/restart`.

use std::{ffi::OsString, path::PathBuf, process::Command};

/// Replaces the current process with the same executable, arguments and
/// environment. The caller passes `args` without `argv[0]`; the new process
/// derives its own zeroth argument from the executable path.
///
/// When `exec` fails, or on platforms without `exec`, exits with code 3 so a
/// service supervisor or container restart policy can pull the service back
/// up. The standard-library wrapper needs no `unsafe` block, keeping the
/// crate-wide `#![forbid(unsafe_code)]` intact.
pub(crate) fn exec_self(exe: PathBuf, args: Vec<OsString>) -> ! {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec() only returns on failure; the environment and working
        // directory are inherited unchanged.
        let error = Command::new(exe).args(args).exec();
        eprintln!("restart failed: {error}");
        std::process::exit(3);
    }
    #[cfg(not(unix))]
    {
        // Windows has no exec; supervisors restart on the exit code instead.
        let _ = (exe, args);
        eprintln!("restart requires a supervisor on this platform");
        std::process::exit(3);
    }
}
