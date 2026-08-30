use std::process::Command;

#[test]
fn shipped_primary_executable_identifies_the_real_proxy() {
    let output = Command::new(env!("CARGO_BIN_EXE_polyguard"))
        .arg("--help")
        .output()
        .expect("run the shipped polyguard executable");
    assert!(
        output.status.success(),
        "polyguard --help failed: {output:?}"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let visible = format!("{stdout}\n{stderr}");
    assert!(
        !visible.contains("Hello, world!"),
        "starter application is still shipped"
    );
    assert!(
        visible.to_ascii_lowercase().contains("polyguard"),
        "help does not identify Polyguard: {visible:?}"
    );
    assert!(
        visible.to_ascii_lowercase().contains("reverse proxy"),
        "help does not expose the application's purpose: {visible:?}"
    );
    assert!(
        visible.contains("HTTP/1.1"),
        "help does not identify the protocol being protected: {visible:?}"
    );
}
