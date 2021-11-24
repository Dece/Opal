Opal
====

Opal is a Gemini server written in Rust. It is meant to serve dynamic content
through CGI and does not serve static files. In a way, it is a companion project
to the [Agate][agate] Gemini server which only serves static files, trying to
focus on a smaller set of features but do them correctly.

[agate]: https://github.com/mbrubeck/agate/

Opal uses the `openssl` Rust bindings, which work with OpenSSL and LibreSSL, so
it should work properly on those platforms. I only support Linux systems but
feel free to patch stuff!



Usage
-----

Use `opal -h` to get a list of options. There is no config file.



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

The `TLS_CLIENT_HASH` is a string that starts with "SHA256:" followed by the
SHA256 digest of the DER representation of the client certificate, as an
uppercase hex-string.

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
