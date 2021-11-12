//! CGI implementation.

use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::path;
use std::process;

use log::{debug, error};

/// General CGI configuration.
pub struct CgiConfig {
    pub root: String,
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

impl crate::server::Connection<'_> {
    /// Process a client request.
    ///
    /// If the CGI process returns successfully, return the requested URL with the process output
    /// so that it can be sent back to the client.
    ///
    /// If an error occurs outside of the CGI process, return a 3-uple with the URL (if it could be
    /// parsed correctly), a Gemini error code and an explanation string to provide to the client.
    pub fn get_response(
        &self,
        request: &[u8],
    ) -> Result<(String, Vec<u8>), (Option<String>, u8, &str)> {
        // Convert the URL to UTF-8.
        let url_str = std::str::from_utf8(&request[..request.len() - 2])
            .map_err(|_| (None, 59, "URL is not valid UTF-8"))?;
        // Parse the URL. The `url` crate normalizes ".." and "/" elements here.
        let url = url::Url::parse(url_str)
            .map_err(|_| (Some(url_str.to_string()), 59u8, "Invalid URL"))?;

        // Get the script path, optionally with CGI's "path info".
        let (script_path, path_info) = self.validate_script_path(&url)?;
        debug!("Script path: \"{}\"", script_path.to_string_lossy());

        // Define a generic "temp failure" error for any other issue.
        let cgi_error = (Some(url_str.to_string()), 40, "Temporary failure");

        // Execute script and return its output.
        let env = self
            .get_cgi_envs(&url, &script_path.to_string_lossy(), &path_info)
            .ok_or_else(|| {
                error!("Can't get required environment variables.");
                cgi_error.to_owned()
            })?;
        let output = process::Command::new(&script_path)
            .env_clear()
            .envs(env)
            .output()
            .map_err(|err| {
                error!("Can't execute script: {}", err);
                cgi_error.to_owned()
            })?;

        Ok((url_str.to_string(), output.stdout))
    }

    /// Return a validated script path from the requested URL along with CGI PATH_INFO.
    ///
    /// A valid path points to an existing, executable file, located within the CGI scripts root.
    /// If any of these condition fails, log the reason and return an appropriate 3-uple for
    /// `get_response`.
    fn validate_script_path(
        &self,
        url: &url::Url,
    ) -> Result<(path::PathBuf, Option<String>), (Option<String>, u8, &str)> {
        // Define a generic "not found" error for most path issues.
        let not_found = (Some(url.as_str().to_string()), 51, "Not found");

        // Find script path from our CGI root and the request.
        let mut path = path::PathBuf::from(&self.cgi_config.root);
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
        if !path.starts_with(&self.cgi_config.root) {
            debug!(
                "Script path \"{}\" is outside of CGI root dir \"{}\".",
                path.to_string_lossy(),
                self.cgi_config.root
            );
            return Err(not_found);
        }

        Ok((path, path_info))
    }

    /// Build environment variables for the CGI process.
    pub fn get_cgi_envs(
        &self,
        url: &url::Url,
        script_path: &str,
        path_info: &Option<String>,
    ) -> Option<HashMap<String, String>> {
        // Start the envs vector with common, nothing-to-compute elements.
        let mut envs = vec![
            ("GATEWAY_INTERFACE", String::from("CGI/1.1")),
            ("REQUEST_METHOD", String::new()),
            ("SERVER_PROTOCOL", String::from("GEMINI")),
            ("SERVER_SOFTWARE", format!("opal/{}", crate_version!())),
            ("GEMINI_DOCUMENT_ROOT", self.cgi_config.root.to_string()),
            ("GEMINI_SCRIPT_FILENAME", script_path.to_string()),
            ("GEMINI_URL", url.to_string()),
            ("GEMINI_URL_PATH", url.path().to_string()),
        ];

        // Next variables must be there but might not be available for some reason: this makes the
        // whole execution fail.

        let remote_addr = self
            .socket
            .peer_addr()
            .map_err(|err| {
                error!("Can't get peer address for CGI envs: {}", err);
                err
            })
            .ok()?;
        envs.push(("REMOTE_ADDR", remote_addr.to_string()));
        envs.push(("REMOTE_HOST", remote_addr.to_string()));

        let server_port = self
            .socket
            .local_addr()
            .map(|address| address.port())
            .map_err(|err| {
                error!("Can't get local address for CGI envs: {}", err);
                err
            })
            .ok()?;
        envs.push(("SERVER_PORT", server_port.to_string()));

        let root_len = self.cgi_config.root.len();
        envs.push(("SCRIPT_NAME", script_path[root_len..].to_string()));

        let server_name = self.tls.sni_hostname().or_else(|| {
            error!("Can't get SNI hostname for SERVER_NAME.");
            None
        })?;
        envs.push(("SERVER_NAME", server_name.to_string()));

        let version = self
            .tls
            .protocol_version()
            .and_then(|v| v.as_str())
            .or_else(|| {
                error!("Can't get TLS version.");
                None
            })?;
        envs.push(("TLS_VERSION", version.to_string()));

        let cipher = self
            .tls
            .negotiated_cipher_suite()
            .and_then(|s| s.suite().as_str())
            .or_else(|| {
                error!("Can't get TLS negociated cipher suite.");
                None
            })?;
        envs.push(("TLS_CIPHER", cipher.to_string()));

        // Next variables are optional.

        if let Some(path_info) = path_info {
            let percent_decode = percent_encoding::percent_decode_str(path_info);
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
        if let Some(certs) = self.tls.peer_certificates() {
            if certs.len() > 0 {
                envs.push(("AUTH_TYPE", String::from("Certificate")));
                let der = &certs[0].0;
                if let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) {
                    envs.push(("REMOTE_USER", get_common_name(cert.subject())));
                    envs.push(("TLS_CLIENT_ISSUER", get_common_name(cert.issuer())));

                    let digest = ring::digest::digest(&ring::digest::SHA256, der);
                    let hex_digest = hexlify(digest.as_ref());
                    let client_hash = String::from("SHA256:") + &hex_digest;
                    envs.push(("TLS_CLIENT_HASH", client_hash));

                    let not_valid_before = cert.validity().not_before.timestamp().to_string();
                    let not_valid_after = cert.validity().not_after.timestamp().to_string();
                    envs.push(("TLS_CLIENT_NOT_BEFORE", not_valid_before));
                    envs.push(("TLS_CLIENT_NOT_AFTER", not_valid_after));
                }
            }
        }

        // CGI standard
        // AUTH_TYPE: OK
        // CONTENT_LENGTH: not affected
        // CONTENT_TYPE: not affected
        // GATEWAY_INTERFACE: OK
        // PATH_INFO: OK, decoded
        // PATH_TRANSLATED: TODO useful?
        // QUERY_STRING: OK still URL-encoded like the standard asks
        // REMOTE_ADDR: OK
        // REMOTE_HOST: use REMOTE_ADDR
        // REMOTE_IDENT: not affected
        // REMOTE_USER: OK
        // REQUEST_METHOD: empty string for compatibility
        // SCRIPT_NAME: OK
        // SERVER_NAME: OK
        // SERVER_PORT: OK
        // SERVER_PROTOCOL: OK
        // SERVER_SOFTWARE: OK

        // Additionally proposed by gmid
        // GEMINI_DOCUMENT_ROOT: OK
        // GEMINI_SCRIPT_FILENAME: OK
        // GEMINI_URL: OK
        // GEMINI_URL_PATH: OK
        // TLS_CLIENT_ISSUER: OK
        // TLS_CLIENT_HASH: OK
        // TLS_VERSION: OK
        // TLS_CIPHER: OK
        // TLS_CIPHER_STRENGTH: pfffff
        // TLS_CLIENT_NOT_AFTER: OK but timestamp
        // TLS_CLIENT_NOT_BEFORE: OK but timestamp

        Some(
            envs.iter()
                .map(|(k, v)| (k.to_string(), v.to_owned()))
                .collect::<HashMap<String, String>>(),
        )
    }
}

/// Helper to get the common name of an x509 name field.
///
/// If there is no common name or it can't be easily converted into a string, return an empty
/// string instead.
fn get_common_name(x509name: &x509_parser::x509::X509Name) -> String {
    x509name
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .or(Some(""))
        .unwrap()
        .to_string()
}

/// Return an hex-string representing the digest data.
fn hexlify(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
