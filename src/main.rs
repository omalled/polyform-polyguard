use std::path::PathBuf;

use polyform_polyguard::{proxy, registered_implementations};

const HELP: &str = "\
Polyguard 0.1.2 — security-first HTTP/1.1 reverse proxy

Usage: polyguard --config <FILE>
       polyguard --check-config <FILE>
       polyguard --implementations

Polyguard compares independently registered protocol-core implementations and
rejects requests when they disagree.
";

fn main() {
    let implementations = registered_implementations();
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        None | Some("-h" | "--help") => print!("{HELP}"),
        Some("--implementations") => {
            if arguments.next().is_some() {
                fail("--implementations takes no arguments");
            }
            for implementation in implementations {
                println!("{}", implementation.id);
            }
        }
        Some("--check-config") => {
            let path = required_path(&mut arguments, "--check-config");
            match proxy::load_config(&path) {
                Ok(_) => println!("configuration is valid"),
                Err(error) => fail(&error.to_string()),
            }
        }
        Some("--config") => {
            let path = required_path(&mut arguments, "--config");
            let config = proxy::load_config(&path).unwrap_or_else(|error| fail(&error.to_string()));
            if let Err(error) = proxy::run(config) {
                fail(&format!("proxy failed: {error}"));
            }
        }
        Some(argument) => {
            fail(&format!("unknown option: {argument}"));
        }
    }
}

fn required_path(arguments: &mut impl Iterator<Item = String>, option: &str) -> PathBuf {
    let path = arguments
        .next()
        .unwrap_or_else(|| fail(&format!("{option} requires a file")));
    if arguments.next().is_some() {
        fail(&format!("{option} accepts exactly one file"));
    }
    PathBuf::from(path)
}

fn fail(message: &str) -> ! {
    eprintln!("polyguard: {message}\n\n{HELP}");
    std::process::exit(2)
}
