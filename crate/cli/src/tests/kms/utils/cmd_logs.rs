use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
};

use assert_cmd::prelude::*;

use crate::tests::PROG_NAME;

static COSMIAN_EXE: OnceLock<PathBuf> = OnceLock::new();

#[allow(deprecated)]
fn resolve_cosmian_exe() -> PathBuf {
    let cmd = Command::cargo_bin(PROG_NAME).unwrap_or_else(|e| {
        panic!("failed to locate `{PROG_NAME}` binary via `Command::cargo_bin`: {e}")
    });

    let path = PathBuf::from(cmd.get_program());
    assert!(
        path.exists(),
        "`cargo_bin({PROG_NAME:?})` resolved to {path:?}, but it does not exist"
    );
    path
}

pub(crate) fn cosmian_exe() -> &'static Path {
    COSMIAN_EXE.get_or_init(resolve_cosmian_exe).as_path()
}

/// Recover output logs from a command call `cmd` and re-inject it into stdio
pub(crate) fn recover_cmd_logs(cmd: &mut Command) -> Output {
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    std::io::stdout()
        .write_all(format!("\r\x1b[K{}", String::from_utf8_lossy(&output.stdout)).as_bytes())
        .unwrap();
    std::io::stderr()
        .write_all(format!("\r\x1b[K{}", String::from_utf8_lossy(&output.stderr)).as_bytes())
        .unwrap();
    output
}
