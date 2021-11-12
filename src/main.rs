use std::fs;
use std::io;
use std::net;
use std::sync::Arc;

#[macro_use]
extern crate clap;

use log::{debug, error, info};

pub mod cgi;
pub mod server;
pub mod tls;

use crate::cgi::CgiConfig;
use crate::server::Server;
use crate::tls::GeminiClientCertVerifier;

/// Load a PEM certificate(s) from disk.
fn load_certificate(path: &str) -> Option<Vec<rustls::Certificate>> {
    let cert_file = match fs::File::open(path) {
        Ok(f) => f,
        Err(err) => {
            error!("Can't open certificate file at {}: {}", path, err);
            return None;
        }
    };
    let mut reader = io::BufReader::new(cert_file);
    Some(
        rustls_pemfile::certs(&mut reader)
            .unwrap()
            .iter()
            .map(|v| rustls::Certificate(v.clone()))
            .collect(),
    )
}

/// Load a PEM private key from disk.
fn load_private_key(path: &str) -> Option<rustls::PrivateKey> {
    let key_file = match fs::File::open(path) {
        Ok(f) => f,
        Err(err) => {
            error!("Can't open private key file at {}: {}", path, err);
            return None;
        }
    };
    let mut reader = io::BufReader::new(key_file);
    loop {
        match rustls_pemfile::read_one(&mut reader) {
            Ok(Some(key)) => match key {
                rustls_pemfile::Item::RSAKey(key) => return Some(rustls::PrivateKey(key)),
                rustls_pemfile::Item::PKCS8Key(key) => return Some(rustls::PrivateKey(key)),
                _ => debug!("Ignored unknown private key type."),
            },
            Ok(None) => {
                error!("No key found in file.");
                return None;
            }
            Err(err) => {
                error!("Can't parse private key data: {}", err);
                return None;
            }
        }
    }
}

fn main() {
    // Get command-line args. Opal does not use config files.
    let matches = clap::App::new("Opal")
        .version(crate_version!())
        .about("Gemini CGI-only server")
        .arg(
            clap::Arg::with_name("address")
                .required(true)
                .short("a")
                .long("address")
                .help("Address to listen to")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("cert")
                .required(true)
                .short("c")
                .long("cert")
                .help("Path to certificate")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("key")
                .required(true)
                .short("k")
                .long("key")
                .help("Path to private key")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("root_path")
                .required(true)
                .short("p")
                .long("root-path")
                .help("Path to CGI scripts root")
                .takes_value(true),
        )
        .get_matches();

    // Setup logging pretty much just like Agate.
    let log_config = env_logger::Env::default().default_filter_or("opal=info");
    env_logger::Builder::from_env(log_config).init();

    // Process command-line args.
    info!("Starting Opal");
    let addr = match matches
        .value_of("address")
        .unwrap()
        .parse::<net::SocketAddr>()
    {
        Ok(a) => a,
        Err(err) => {
            error!(
                "Invalid listening address (wrong format or port missing?): {}",
                err
            );
            return;
        }
    };
    let server_certs = match load_certificate(matches.value_of("cert").unwrap()) {
        Some(v) if v.len() > 0 => v,
        Some(_) => {
            error!("No valid certificate found.");
            return;
        }
        None => return,
    };
    let server_key = match load_private_key(matches.value_of("key").unwrap()) {
        Some(k) => k,
        None => return,
    };
    let cgi_root = match fs::canonicalize(matches.value_of("root_path").unwrap()) {
        Ok(p) => p.to_str().unwrap().to_string(),
        Err(err) => {
            error!("Invalid CGI root path: {}", err);
            return;
        }
    };
    let cgi_config = CgiConfig { root: cgi_root };

    // Setup TLS server.
    let config = Arc::new(
        match rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(GeminiClientCertVerifier::new())
            .with_single_cert(server_certs, server_key)
        {
            Ok(c) => c,
            Err(err) => {
                error!("Invalid certificate or private key provided: {}", err);
                return;
            }
        },
    );
    let mut listener = match mio::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(err) => {
            error!("Can't listen on port: {}", err);
            return;
        }
    };
    let listener_token = mio::Token(0);
    let mut poll = mio::Poll::new().unwrap();
    if let Err(err) =
        poll.registry()
            .register(&mut listener, listener_token, mio::Interest::READABLE)
    {
        error!("Can't setup poll listener: {}", err);
        return;
    }
    let mut server = Server::new(listener, config, &cgi_config);
    let mut events = mio::Events::with_capacity(256);
    loop {
        if let Err(err) = poll.poll(&mut events, None) {
            debug!("Poll failed: {}", err);
            continue;
        }
        for event in events.iter() {
            if event.token() == listener_token {
                if let Err(err) = server.accept(poll.registry()) {
                    error!("Could not accept socket: {}", err);
                }
            } else {
                server.handle_event(poll.registry(), &event);
            }
        }
    }
}
