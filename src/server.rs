//! Server listening loop and connection basics.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net;
use std::sync::Arc;

use log::{debug, error, info};

use crate::cgi::CgiConfig;

/// TCP server, listening for clients opening TLS connections.
pub struct Server<'a> {
    pub config: Arc<rustls::ServerConfig>,
    pub cgi_config: &'a CgiConfig,
    listener: mio::net::TcpListener,
    connections: HashMap<mio::Token, Connection<'a>>,
    next_id: usize,
}

impl<'a> Server<'a> {
    /// Create a new Server.
    pub fn new(
        listener: mio::net::TcpListener,
        config: Arc<rustls::ServerConfig>,
        cgi_config: &'a CgiConfig,
    ) -> Self {
        Server {
            config,
            listener,
            connections: HashMap::new(),
            next_id: 2,
            cgi_config,
        }
    }

    /// Accept incoming client connections forever.
    pub fn accept(&mut self, registry: &mio::Registry) -> Result<(), io::Error> {
        loop {
            match self.listener.accept() {
                Ok((socket, addr)) => {
                    debug!("Connection from {:?}", addr);
                    let tls = match rustls::ServerConnection::new(Arc::clone(&self.config)) {
                        Ok(c) => c,
                        Err(err) => {
                            error!("Could not create server connection: {}", err);
                            continue;
                        }
                    };
                    let token = mio::Token(self.next_id);
                    self.next_id += 1;
                    let mut connection = Connection::new(socket, token, tls, self.cgi_config);
                    connection.register(registry);
                    self.connections.insert(token, connection);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    error!("Error while accepting connection: {}", err);
                    return Err(err);
                }
            }
        }
    }

    /// Pass MIO events to corresponding connections.
    pub fn handle_event(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        let token = event.token();
        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .ready(registry, event);
            if self.connections[&token].state == ConnectionState::Closed {
                self.connections.remove(&token);
            }
        }
    }
}

/// Connection state, mostly used for graceful shutdowns.
#[derive(PartialEq)]
pub enum ConnectionState {
    Open,
    Closing,
    Closed,
}

/// A once open connection; hold the TCP and TLS states, as well as the incoming client data.
pub struct Connection<'a> {
    pub cgi_config: &'a CgiConfig,
    pub socket: mio::net::TcpStream,
    pub tls: rustls::ServerConnection,
    pub token: mio::Token,
    pub state: ConnectionState,
    buffer: Vec<u8>,
    received: usize,
}

impl<'a> Connection<'a> {
    /// Create a new Connection.
    fn new(
        socket: mio::net::TcpStream,
        token: mio::Token,
        tls_connection: rustls::ServerConnection,
        cgi_config: &'a CgiConfig,
    ) -> Self {
        Connection {
            socket,
            token,
            state: ConnectionState::Open,
            tls: tls_connection,
            buffer: vec![0; 1026],
            received: 0,
            cgi_config,
        }
    }

    /// Process an event.
    fn ready(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        if event.is_readable() {
            self.read_tls();
            self.read_plain();
        }
        if event.is_writable() {
            self.write_tls_with_errors();
        }
        if self.state == ConnectionState::Closing {
            if let Err(err) = self.socket.shutdown(net::Shutdown::Both) {
                error!("Could not properly shutdown socket: {}", err);
            }
            self.state = ConnectionState::Closed;
            registry.deregister(&mut self.socket).unwrap();
        } else {
            let event_set = self.event_set();
            registry
                .reregister(&mut self.socket, self.token, event_set)
                .unwrap();
        }
    }

    /// Read data from the TLS tunnel; if enough data is read, new packets are processed and can be
    /// later read with `read_plain`.
    fn read_tls(&mut self) {
        match self.tls.read_tls(&mut self.socket) {
            Err(err) => {
                if err.kind() != io::ErrorKind::WouldBlock {
                    error!("TLS read error: {}", err);
                    self.state = ConnectionState::Closing;
                }
                return;
            }
            Ok(num_bytes) if num_bytes == 0 => {
                self.state = ConnectionState::Closing;
                return;
            }
            _ => {}
        };

        if let Err(err) = self.tls.process_new_packets() {
            error!("Can't process packet: {}", err);
            self.write_tls_with_errors();
            self.state = ConnectionState::Closing;
        }
    }

    /// Process packets with incoming data from a client.
    fn read_plain(&mut self) {
        if let Ok(io_state) = self.tls.process_new_packets() {
            let to_read = io_state.plaintext_bytes_to_read();
            if to_read > 0 {
                let mut buffer = vec![0u8; to_read];
                self.tls.reader().read(&mut buffer).unwrap();
                self.handle_incoming_data(&buffer);
            }
        }
    }

    /// Process received client data as a Gemini request; it either is a self-contained
    fn handle_incoming_data(&mut self, data: &[u8]) {
        // The connection buffer should never exceed 1026 bytes: 1024 URL bytes plus \r\n.
        if data.len() + self.received > 1026 {
            error!("URL queried is longer 1024 bytes, discarding.");
            self.state = ConnectionState::Closing;
            return;
        }
        // If the URL requested is contained within that single data packet, process it without
        // copying stuff.
        if self.received == 0 && data.ends_with(b"\r\n") {
            self.process_buffer(data);
        }
        // Else append received data into the connection buffer and try to process it.
        else {
            let buffer_end = self.received + data.len();
            self.buffer[self.received..buffer_end].copy_from_slice(data);
            self.received = buffer_end;
            if self.buffer[..self.received].ends_with(b"\r\n") {
                self.process_buffer(&self.buffer.clone());
            }
        }
    }

    /// Respond to a client request. Whether the request succeeds or not, a response is sent and
    /// the connection is closed.
    fn process_buffer(&mut self, buffer: &[u8]) {
        // Get appropriate response from either Opal or the CGI process.
        let response: Vec<u8> = match self.get_response(buffer) {
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
        if let Err(err) = self.tls.writer().write_all(&response) {
            error!("Error while writing TLS data: {}", err);
        }
        // Properly close the connection.
        self.tls.send_close_notify();
        self.state = ConnectionState::Closing;
    }

    /// Write TLS data in the TCP socket.
    fn write_tls(&mut self) -> io::Result<usize> {
        self.tls.write_tls(&mut self.socket)
    }

    /// Call `write_tls` and mark connection as closing on error.
    fn write_tls_with_errors(&mut self) {
        if let Err(err) = self.write_tls() {
            error!("TLS write error after errors: {}", err);
            self.state = ConnectionState::Closing;
        }
    }

    /// Register the connection into the MIO registry using its own token.
    fn register(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    /// Return what IO events we're currently waiting for, based on wants_read/wants_write.
    fn event_set(&self) -> mio::Interest {
        let r = self.tls.wants_read();
        let w = self.tls.wants_write();
        if r && w {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if w {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }
}
