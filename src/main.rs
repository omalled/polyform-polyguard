use std::path::PathBuf;

use polyform_polyguard::{nginx, proxy, registered_implementations};

const HELP: &str = concat!(
    "Polyguard ",
    env!("CARGO_PKG_VERSION"),
    " — security-first HTTP/1.1 reverse proxy

Usage: polyguard --config <FILE>
       polyguard --check-config <FILE>
       polyguard --nginx-config <FILE>
       polyguard --check-nginx <FILE>
       polyguard --import-nginx <FILE>
       polyguard --implementations

Polyguard compares independently registered protocol-core implementations and
rejects requests when they disagree.
"
);

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
            let reload_path = path.clone();
            if let Err(error) = proxy::run_reloading(config, move || {
                proxy::load_config(&reload_path).map_err(std::io::Error::other)
            }) {
                fail(&format!("proxy failed: {error}"));
            }
        }
        Some("--check-nginx") => {
            let path = required_path(&mut arguments, "--check-nginx");
            match nginx::load_config(&path) {
                Ok(config) => {
                    println!(
                        "Nginx configuration is compatible ({} listener(s), {} site(s))",
                        config.listeners.len() + 1,
                        config.sites.len()
                    );
                }
                Err(error) => fail_nginx(error),
            }
        }
        Some("--nginx-config") => {
            let path = required_path(&mut arguments, "--nginx-config");
            let config = nginx::load_config(&path).unwrap_or_else(|error| fail_nginx(error));
            let reload_path = path.clone();
            if let Err(error) = proxy::run_reloading(config, move || {
                nginx::load_config(&reload_path).map_err(std::io::Error::other)
            }) {
                fail(&format!("proxy failed: {error}"));
            }
        }
        Some("--import-nginx") => {
            let path = required_path(&mut arguments, "--import-nginx");
            let config = nginx::load_config(&path).unwrap_or_else(|error| fail_nginx(error));
            let serialized = toml::to_string_pretty(&config).unwrap_or_else(|error| {
                fail(&format!("could not serialize configuration: {error}"))
            });
            print!("{serialized}");
        }
        Some(argument) => {
            fail(&format!("unknown option: {argument}"));
        }
    }
}

fn fail_nginx(error: nginx::NginxError) -> ! {
    if let nginx::NginxError::Unsupported(issues) = &error {
        for issue in issues {
            eprintln!("{issue}");
        }
    }
    fail(&error.to_string())
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
