//! The binary as a caller sees it: its exit status and what it logs.

use std::path::Path;
use std::process::Command;

#[test]
fn a_failed_run_exits_nonzero_and_logs_the_whole_error_chain() {
    let patches_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("no-such-patches-dir");
    let output = Command::new(env!("CARGO_BIN_EXE_slipmesh-routeros"))
        .args(["--node", "node-a", "--patches-dir"])
        .arg(&patches_dir)
        .env_remove("RUST_LOG")
        .output()
        .unwrap();

    assert!(!output.status.success(), "{:?}", output.status);
    let log = String::from_utf8(output.stdout).unwrap();
    assert!(log.contains("routeros failed"), "{log}");
    assert_eq!(
        log.matches("failed to read the patch file").count(),
        1,
        "{log}"
    );
    let patch_file = patches_dir.join("node-a.yaml");
    assert_eq!(
        log.matches(&*patch_file.to_string_lossy()).count(),
        1,
        "{log}"
    );
    assert!(log.contains("No such file or directory"), "{log}");
}
