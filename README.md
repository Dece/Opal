Opal
====

Opal is a Gemini server written in Rust. It is meant to serve dynamic content
through CGI and does not serve static files. In a way, it is a companion project
to the [Agate][agate] Gemini server which only serves static files. The
project's goals are:

- Focus on a small set of features (around CGI) but do them correctly.
- Be nice with old/stupid hardware (TLS 1.2 is OK, be efficient, etc).
- Don't add features (see the roadmap at the end of this file).
- Try to keep resources (binary size, memory, etc) under tight control.

Opal uses the `openssl` Rust bindings, which work with OpenSSL and LibreSSL, so
it should work properly on those platforms. I currently only support Linux
systems but if there is interest in other platforms let's do this together!

Opal is licensed as GPLv3.

[agate]: https://github.com/mbrubeck/agate/



Installation
------------

### Pre-compiled releases

Binary releases for 64-bit Linux systems are available on [my Gitea][gitea-rel]
and on [Github][gh-rel].

[gitea-rel]: https://git.dece.space/Dece/Opal/releases
[gh-rel]: https://github.com/Dece/Opal/releases

### Compiling from sources

Compiling Opal requires Cargo installed with the stable Rust toolchain.



Usage
-----

Use `opal -h` to get a list of options. There is no config file, every setting
can be configured from the command line.

- `-a, --address <address>`: specify the address(es) to listen to.
- `-c, --cert <cert>`: server certificate path.
- `-k, --key <key>`: server private key path.
- `-r, --root-path <root_path>`: path to CGI scripts root.
- `-e, --env <key=value>`: additional environment variables for CGI scripts;
    this option can be used multiple times.

You can specify multiple addresses to listen to by using several `-a` options.
Note that if you just want to listen to both IPv4 and IPv6 on any interface,
listening only on `[::]:1965` should suffice for systems with dual-stack
enabled (default on many Linux systems, maybe not BSD).

### Systemd

I personally run Opal as a Systemd service. Here is an example unit file:

``` ini
[Unit]
Description=Opal Gemini server

[Service]
WorkingDirectory=/home/gemini/opal
User=gemini
Group=gemini
ExecStart=/usr/local/bin/opal -a "[::]:1966" -c certs/cert.pem -k certs/key.pem -r cgi -e STORAGE_ROOT=storage
Restart=always
RestartSec=1
SyslogIdentifier=opal
# Security options:
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=tmpfs
BindReadOnlyPaths="/home/gemini/opal"
BindPaths="/home/gemini/opal/storage"

[Install]
WantedBy=multi-user.target
```

- Opal has been installed in `/usr/local/bin`
- The directory `/home/gemini/opal` contains the directories `certs`, `cgi` and
    `storage`, for certificates, the CGI scripts and a storage path.
- The `/home` directory is not readable, except for `/home/gemini/opal` which is
    read-only, except for the `storage` directory which is writeable.

This is just an example, please do not mindlessly copy and paste it without
understanding what the options stand for. It is also possible to use a chrooted
environment or the Systemd equivalent option RootDirectory. Your choice!



CGI support
-----------

Opal tries to implement [RFC 3875][rfc3875] (CGI 1.1) and provides all the
required environment variables to processes. It also add a bunch of Gemini
specific variables, like a lot of other servers (Gemserv, Gmid, Gmnisrv, …). The
environment for the subprocess is cleaned and should only contain those
variables.

[rfc3875]: https://datatracker.ietf.org/doc/html/rfc3875

| Presence    | Variable               | Description                                          |
|-------------|------------------------|------------------------------------------------------|
| always      | GATEWAY_INTERFACE      | "CGI/1.1"                                            |
| always      | REMOTE_ADDR            | Peer IP address and port                             |
| always      | REMOTE_HOST            | Same as REMOTE_ADDR                                  |
| always      | REQUEST_METHOD         | Empty string for compatibility                       |
| always      | SCRIPT_NAME            | Script name part of the URL path                     |
| always      | SERVER_NAME            | Hostname used for SNI                                |
| always      | SERVER_PORT            | Port where the request has been received             |
| always      | SERVER_PROTOCOL        | "GEMINI"                                             |
| always      | SERVER_SOFTWARE        | "opal/version", e.g. "opal/0.1.0"                    |
| always      | GEMINI_DOCUMENT_ROOT   | CGI root                                             |
| always      | GEMINI_SCRIPT_FILENAME | CGI script that matched the URL path                 |
| always      | GEMINI_URL             | Full URL, normalized                                 |
| always      | GEMINI_URL_PATH        | URL path, normalized                                 |
| always      | TLS_VERSION            | TLS version, e.g. "TLSv1.3"                          |
| always      | TLS_CIPHER             | TLS cipher suite, e.g. "TLS_AES_256_GCM_SHA384"      |
| optional    | PATH_INFO              | Path passed to the CGI process after the script name |
| optional    | QUERY_STRING           | Query string if provided, still URL-encoded          |
| client cert | AUTH_TYPE              | "CERTIFICATE" if one is provided                     |
| client cert | REMOTE_USER            | Subject common name (empty if unavailable)           |
| client cert | TLS_CLIENT_ISSUER      | Issuer common name (empty if unavailable)            |
| client cert | TLS_CLIENT_HASH        | Digest of the DER reprensetation of the cert         |
| client cert | TLS_CLIENT_NOT_AFTER   | Validity end date, RFC 3339 format                   |
| client cert | TLS_CLIENT_NOT_BEFORE  | Validity start date, RFC 3339 format                 |

Opal does not provide `CONTENT_LENGTH`, `CONTENT_TYPE`, `REMOTE_IDENT` because
they do not make much sense in Gemini. `PATH_TRANSLATED` is also not implemented
by pure laziness.

The `TLS_CLIENT_HASH` is a string that starts with the 7 bytes `SHA256:`
followed by the SHA256 digest of the DER representation of the client
certificate, as an uppercase hex-string.

It can be a bit confusing which variable represent what data, especially those
related to the URL and the path. Take the following request as example:
`gemini://localhost/env/sub1/sub2?search=élément`. Suppose our CGI root, in
`/cgi`, contains the executable script named `env`. The variables will be:

```
GEMINI_DOCUMENT_ROOT=/cgi
GEMINI_SCRIPT_FILENAME=/cgi/env
GEMINI_URL=gemini://localhost/env/sub1/sub2?search=%C3%A9l%C3%A9ment
GEMINI_URL_PATH=/env/sub1/sub2
SCRIPT_NAME=/env
PATH_INFO=/sub1/sub2
QUERY_STRING=search=%C3%A9l%C3%A9ment
```



Roadmap
-------

Things that might end up in Opal one day:

- Support SCGI; a bit more complex but should save resources on smol hardware.

Things that probably won't be considered:

- Serve static files; so many other servers do that correctly already!
- Any kind of security mechanism that is not properly motivated.
- FastCGI; un-smol…
