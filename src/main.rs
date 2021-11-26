use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::net;
use std::path;
use std::process;
use std::sync::Arc;
use std::thread;

#[macro_use]
extern crate clap;

use chrono::offset::TimeZone;
use log::{debug, error, info, warn};
use openssl::{asn1, ssl, x509};

/// General CGI configuration.
#[derive(Clone)]
struct CgiConfig {
    root: String,
    envs: HashMap<String, String>,
}

fn main() {
    process::exit(match run() {
        Ok(()) => 0,
        Err(err) => err,
    })
}

/// Run Opal: parse CLI args and listen for clients.
fn run() -> Result<(), i32> {
    // Get command-line args. Opal does not use config files.
    let matches = clap::App::new("Opal")
        .version(crate_version!())
        .about("Gemini CGI server")
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
                .short("r")
                .long("root-path")
                .help("Path to CGI scripts root")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("env")
                .short("e")
                .long("env")
                .help("Environment variable for CGI scripts")
                .takes_value(true)
                .multiple(true),
        )
        .get_matches();

    // Setup logging pretty much just like Agate.
    let log_config = env_logger::Env::default().default_filter_or("opal=info");
    env_logger::Builder::from_env(log_config).init();

    // Process command-line args.
    info!("Starting Opal");

    let cgi_root = fs::canonicalize(matches.value_of("root_path").unwrap())
        .map(|p| p.to_str().unwrap().to_string())
        .map_err(|err| {
            error!("Invalid CGI root path: {}", err);
            1
        })?;
    let mut cgi_envs = HashMap::new();
    if let Some(envs) = matches.values_of("env") {
        envs.for_each(|env| {
            if let Some((key, value)) = env.split_once("=") {
                cgi_envs.insert(key.to_string(), value.to_string());
            }
        })
    }
    let cgi_config = CgiConfig {
        root: cgi_root,
        envs: cgi_envs,
    };

    // Setup TLS server.
    let acceptor = create_ssl_acceptor(
        matches.value_of("cert").unwrap(),
        matches.value_of("key").unwrap(),
    )
    .map_err(|err| run_failure("Could not create TLS acceptor", &err))?;

    let address = matches.value_of("address").unwrap();
    let listener = net::TcpListener::bind(address)
        .map_err(|err| run_failure("Could not create TCP listener", &err))?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                let cgi_config = cgi_config.clone();
                thread::spawn(move || match acceptor.accept(stream) {
                    Ok(mut tls_stream) => handle_client(&mut tls_stream, &cgi_config),
                    Err(err) => error!("Can't initiate TLS stream: {}", err),
                });
            }
            Err(err) => {
                error!("Can't accept connection: {}", err);
            }
        }
    }
    Ok(())
}

/// Log an error message consisting of `msg` followed by `err` and return 1.
fn run_failure(msg: &str, err: &impl std::fmt::Display) -> i32 {
    error!("{}: {}", msg, err);
    1
}

/// Create a new TLS acceptor that can be cloned for incoming connections.
fn create_ssl_acceptor(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<ssl::SslAcceptor>, ssl::Error> {
    let mut acceptor = ssl::SslAcceptor::mozilla_intermediate_v5(ssl::SslMethod::tls())?;
    acceptor.set_certificate_chain_file(cert_path)?;
    acceptor.set_private_key_file(key_path, ssl::SslFiletype::PEM)?;
    acceptor.check_private_key()?;
    acceptor.set_verify_callback(ssl::SslVerifyMode::PEER, |ver, store| {
        ver || match verify_client_cert(store) {
            Ok(res) => res,
            Err(e) => {
                error!("Can't validate client cert: {}", e);
                false
            }
        }
    });
    Ok(Arc::new(acceptor.build()))
}

/// Verify a Gemini client certificate.
///
/// This is standard certificate verification but we use the certificate's own public key to verify
/// the signature, so self-signed certificates are as valid as those with a chain.
fn verify_client_cert(store: &mut x509::X509StoreContextRef) -> Result<bool, String> {
    let cert = store.current_cert().ok_or_else(|| "no cert in store")?;
    cert.verify(
        cert.public_key()
            .map_err(|_| "can't use cert public key")?
            .as_ref(),
    )
    .map_err(|err| format!("verification failed: {}", err))
}

/// Handle a new client's request.
fn handle_client(tls_stream: &mut ssl::SslStream<net::TcpStream>, cgi_config: &CgiConfig) {
    // The connection buffer should never exceed 1026 bytes: 1024 URL bytes plus \r\n.
    let mut request = vec![0u8; 1026];
    let read_bytes = match tls_stream.ssl_read(&mut request) {
        Ok(n) if n > 0 => n,
        Ok(_) => {
            error!("Empty request");
            return;
        }
        Err(err) => {
            error!("TLS read error: {}", err);
            return;
        }
    };
    if &request[(read_bytes - 2)..read_bytes] != b"\r\n" {
        error!("Request does not end with \\r\\n.");
        return;
    }

    // Get appropriate response from either Opal or the CGI process.
    let response: Vec<u8> = match get_response(&request[..read_bytes], cgi_config, &tls_stream) {
        Ok((url, data)) => {
            info!("\"{}\" → reply {} bytes", url, data.len());
            data
        }
        Err((url, code, meta)) => {
            info!(
                "\"{}\" → {} \"{}\"",
                url.or(Some("<invalid URL>".to_string())).unwrap(),
                code,
                meta
            );
            format!("{} {}\r\n", code, meta).as_bytes().to_vec()
        }
    };

    // Whether the request succeeded or not, send the response.
    if let Err(err) = tls_stream.ssl_write(&response) {
        error!("Error while writing TLS data: {}", err);
    }

    // Properly close the connection with a close notify.
    match tls_stream.shutdown() {
        Ok(shutdown) => debug!("Connection shutdown (state: {:?})", shutdown),
        Err(err) => error!("Could not properly shutdown: {}", err),
    }
}

/// Process a client request.
///
/// If the CGI process returns successfully, return the requested URL with the process output
/// so that it can be sent back to the client.
///
/// If an error occurs outside of the CGI process, return a 3-uple with the URL (if it could be
/// parsed correctly), a Gemini error code and an explanation string to provide to the client.
fn get_response(
    request: &[u8],
    cgi_config: &CgiConfig,
    tls: &ssl::SslStream<net::TcpStream>,
) -> Result<(String, Vec<u8>), (Option<String>, u8, &'static str)> {
    // Convert the URL to UTF-8.
    let url_str = std::str::from_utf8(&request[..request.len() - 2])
        .map_err(|_| (None, 59, "URL is not valid UTF-8"))?;
    // Parse the URL. The `url` crate normalizes ".." and "/" elements here.
    let url =
        url::Url::parse(url_str).map_err(|_| (Some(url_str.to_string()), 59u8, "Invalid URL"))?;

    // Get the script path, optionally with CGI's "path info".
    let (script_path, path_info) = validate_script_path(&url, cgi_config)?;
    let script_path = script_path.to_string_lossy().into_owned();
    debug!("Script path: \"{}\"", script_path);

    // Define a generic "temp failure" error for any other issue.
    let cgi_error = (Some(url_str.to_string()), 40, "Temporary failure");

    // Start the envs vector with common, nothing-to-compute elements.
    let mut envs = vec![
        ("GATEWAY_INTERFACE", String::from("CGI/1.1")),
        ("REQUEST_METHOD", String::new()),
        ("SERVER_PROTOCOL", String::from("GEMINI")),
        ("SERVER_SOFTWARE", format!("opal/{}", crate_version!())),
        ("GEMINI_DOCUMENT_ROOT", cgi_config.root.to_string()),
        ("GEMINI_SCRIPT_FILENAME", script_path.clone()),
        ("GEMINI_URL", url.to_string()),
        ("GEMINI_URL_PATH", url.path().to_string()),
    ];

    // Next variables must be there but might not be available for some reason: this makes the
    // whole execution fail.
    let remote_addr = tls.get_ref().peer_addr().map_err(|err| {
        error!("Can't get peer address for CGI envs: {}", err);
        cgi_error.to_owned()
    })?;
    envs.push(("REMOTE_ADDR", remote_addr.to_string()));
    envs.push(("REMOTE_HOST", remote_addr.to_string()));
    envs.push((
        "SERVER_PORT",
        tls.get_ref()
            .local_addr()
            .map(|address| address.port())
            .map_err(|err| {
                error!("Can't get local address for CGI envs: {}", err);
                cgi_error.to_owned()
            })?
            .to_string(),
    ));
    envs.push((
        "SCRIPT_NAME",
        script_path[cgi_config.root.len()..].to_string(),
    ));
    envs.push((
        "SERVER_NAME",
        tls.ssl()
            .servername(ssl::NameType::HOST_NAME)
            .ok_or_else(|| {
                error!("Can't get SNI hostname for SERVER_NAME.");
                cgi_error.to_owned()
            })?
            .to_string(),
    ));
    envs.push(("TLS_VERSION", tls.ssl().version_str().to_string()));
    envs.push((
        "TLS_CIPHER",
        tls.ssl()
            .current_cipher()
            .and_then(|c| c.standard_name())
            .ok_or_else(|| {
                error!("Can't get TLS negociated cipher suite.");
                cgi_error.to_owned()
            })?
            .to_string(),
    ));

    // Next variables are optional.
    if let Some(path_info) = path_info {
        let percent_decode = percent_encoding::percent_decode_str(&path_info);
        match percent_decode.decode_utf8() {
            Ok(path_info) => {
                envs.push(("PATH_INFO", path_info.to_string()));
            }
            Err(err) => {
                error!("CGI PATH_INFO decoded into invalid UTF-8: {}", err);
            }
        };
    }
    if let Some(query) = url.query() {
        envs.push(("QUERY_STRING", query.to_string()));
    }

    // Variables related to client certificates.
    if let Some(cert) = tls.ssl().peer_certificate() {
        envs.push(("AUTH_TYPE", String::from("CERTIFICATE")));
        envs.push(("REMOTE_USER", get_x509_cn(cert.subject_name())));
        envs.push(("TLS_CLIENT_ISSUER", get_x509_cn(cert.issuer_name())));
        let digest = cert
            .digest(openssl::hash::MessageDigest::sha256())
            .map_err(|err| {
                error!("Can't digest certificate: {}", err);
                cgi_error.to_owned()
            })?;
        let hex_digest = hexlify(digest.as_ref());
        let client_hash = String::from("SHA256:") + &hex_digest;
        envs.push(("TLS_CLIENT_HASH", client_hash));
        let dt_format_failed = || {
            error!("Can't format date/time");
            cgi_error.to_owned()
        };
        envs.push((
            "TLS_CLIENT_NOT_BEFORE",
            format_rfc3339(cert.not_before()).ok_or_else(dt_format_failed)?,
        ));
        envs.push((
            "TLS_CLIENT_NOT_AFTER",
            format_rfc3339(cert.not_after()).ok_or_else(dt_format_failed)?,
        ));
    }

    // Collect our variables into a hashmap before execution.
    let envs = envs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_owned()))
        .collect::<HashMap<String, String>>();

    // Run the subprocess!
    let output = process::Command::new(script_path)
        .env_clear()
        .envs(&envs)
        .envs(&cgi_config.envs)
        .output()
        .map_err(|err| {
            error!("Can't execute script: {}", err);
            cgi_error.to_owned()
        })?;

    if output.stderr.len() > 0 {
        warn!("Process standard error:");
        if let Ok(stderr) = std::str::from_utf8(output.stderr.as_slice()) {
            for line in stderr.lines() {
                warn!("  {}", line);
            }
        } else {
            error!("Can't decode process standard error.")
        }
    }

    Ok((url_str.to_string(), output.stdout))
}

/// Return a validated script path from the requested URL along with CGI PATH_INFO.
///
/// A valid path points to an existing, executable file, located within the CGI scripts root.
/// If any of these condition fails, log the reason and return an appropriate 3-uple for
/// `get_response`.
fn validate_script_path(
    url: &url::Url,
    cgi_config: &CgiConfig,
) -> Result<(path::PathBuf, Option<String>), (Option<String>, u8, &'static str)> {
    // Define a generic "not found" error for most path issues.
    let not_found = (Some(url.as_str().to_string()), 51, "Not found");

    // Find script path from our CGI root and the request.
    let mut path = path::PathBuf::from(&cgi_config.root);
    let mut segments = url.path_segments().ok_or_else(|| {
        error!("Can't get path segments from URL");
        not_found.to_owned()
    })?;
    // We incrementally push path segments after our CGI root to find the first path that
    // represents an executable file.
    let mut found_script = false;
    loop {
        let segment = segments.next();
        if segment.is_none() {
            break;
        }
        let decoded_segment = percent_encoding::percent_decode_str(segment.unwrap())
            .decode_utf8()
            .map_err(|err| {
                error!("Path segment decoded into invalid UTF-8: {}", err);
                not_found.to_owned()
            })?;
        path.push(decoded_segment.into_owned());
        // If that path is not an executable file, continue with the next segment.
        if path.is_file() && is_executable(&path) {
            found_script = true;
            break;
        }
    }
    if !found_script {
        error!("No script found along path \"{}\".", path.to_string_lossy());
        return Err(not_found);
    }

    // Collect the remaining segments into the CGI "path info" value.
    let rem_segments = segments.collect::<Vec<&str>>();
    let path_info = if rem_segments.len() > 0 {
        Some(String::from("/") + &rem_segments.join("/"))
    } else {
        None
    };

    // Just for safety, check that the now-canonicalized path is within the CGI root.
    if !path.starts_with(&cgi_config.root) {
        debug!(
            "Script path \"{}\" is outside of CGI root dir \"{}\".",
            path.to_string_lossy(),
            cgi_config.root
        );
        return Err(not_found);
    }

    Ok((path, path_info))
}

/// Return true if this path has executable bits set on Unix systems.
///
/// If for some reason we can't get the mode information (not on Unix or some error occured),
/// return false.
fn is_executable(path: &path::Path) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            mode & 0o111 != 0
        }
        Err(err) => {
            error!(
                "Can't get metadata for \"{}\": {}",
                path.to_string_lossy(),
                err
            );
            false
        }
    }
}

/// Helper to get the common name of an x509 name field.
///
/// If there is no common name or it can't be easily converted into a string, return an empty
/// string instead.
fn get_x509_cn(name_ref: &x509::X509NameRef) -> String {
    for entry in name_ref.entries_by_nid(openssl::nid::Nid::COMMONNAME) {
        match entry.data().as_utf8() {
            Ok(s) => return s.to_string(),
            Err(err) => {
                error!("Can't convert ASN.1 string to UTF-8: {}", err);
                return String::new();
            }
        }
    }
    String::new()
}

/// Return an hex-string representing the digest data.
fn hexlify(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len() * 2);
    digest
        .iter()
        .for_each(|b| write!(&mut s, "{:02X}", b).unwrap());
    s
}

/// Format an ASN.1 time into an RFC 3339 representation. What the hell?
fn format_rfc3339(asn1_time: &asn1::Asn1TimeRef) -> Option<String> {
    asn1::Asn1Time::from_unix(0)
        .map_err(|err| err.to_string())
        .and_then(|epoch| epoch.diff(asn1_time).map_err(|err| err.to_string()))
        .and_then(|diff| {
            let secs = diff.days as i64 * 86400i64 + diff.secs as i64;
            chrono::offset::Utc
                .timestamp_opt(secs, 0)
                .single()
                .ok_or_else(|| "invalid timestamp".to_owned())
        })
        .and_then(|dt| Ok(dt.to_rfc3339()))
        .ok()
}
