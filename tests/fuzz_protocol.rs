use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

fn invoke(request: &Value) -> (Vec<u8>, Vec<u8>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_polyguard-fuzz"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start differential driver");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(request).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    (output.stdout, output.stderr)
}

#[test]
fn generate_is_deterministic_and_writes_one_json_response() {
    let request = json!({"schema_version":1,"operation":"generate","function":"parse_request_line","seed":7,"case":0});
    let first = invoke(&request);
    let second = invoke(&request);
    assert_eq!(first, second);
    assert!(
        first.1.is_empty(),
        "successful diagnostics leaked to stderr"
    );
    assert_eq!(first.0.iter().filter(|&&byte| byte == b'\n').count(), 1);
    let response: Value = serde_json::from_slice(&first.0).unwrap();
    assert_eq!(response["valid"], true);
    assert!(response["input"].is_object());
    assert!(response["outcomes"].is_array());
}

#[test]
fn evaluate_preserves_the_supplied_input_exactly() {
    let input = json!({"code":"accepted","upstream_reached":true,"extra":[1,null,"x"]});
    let request = json!({"schema_version":1,"operation":"evaluate","function":"classify_telemetry_outcome","input":input});
    let (stdout, stderr) = invoke(&request);
    assert!(stderr.is_empty());
    let response: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(response["valid"], true);
    assert_eq!(response["input"], input);
    assert!(response["outcomes"].is_array());
}
