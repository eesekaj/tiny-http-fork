
use std::{io, net::ToSocketAddrs};

use crate::connection::ConfigListenAddr;

/// Represents the parameters required to create a server.
#[derive(Debug, Clone)]
pub struct ServerConfig 
{
    /// The addresses to try to listen to.
    pub addr: ConfigListenAddr,

    /// If `Some`, then the server will use SSL to encode the communications.
    pub ssl: Option<SslConfig>,

    /// Minimum threads which always runs.
    pub min_threads: Option<usize>,

    /// Maximum threads which can be allocated.
    pub max_threads: Option<usize>,
}

impl ServerConfig
{
    pub 
    fn new_http<A>(addr: A) -> io::Result<ServerConfig>
    where
        A: ToSocketAddrs,
    {
        Ok(
            ServerConfig 
            {
                addr: 
                    ConfigListenAddr::from_socket_addrs(addr)?,
                ssl: 
                    None,
                min_threads: 
                    None,
                max_threads: 
                    None,
            }
        )
    }

    pub 
    fn set_min_threads(mut self, cnt: usize) -> Self
    {
        self.min_threads = Some(cnt);

        return self;
    }

    pub 
    fn set_max_threads(mut self, cnt: usize) -> Self
    {
        self.max_threads = Some(cnt);

        return self;
    }

    pub 
    fn set_ssl(mut self, ssl: SslConfig) -> Self
    {
        self.ssl = Some(ssl);

        return self;
    }
}

/// Configuration of the server for SSL.
#[derive(Debug, Clone)]
pub struct SslConfig 
{
    /// Contains the public certificate to send to clients.
    pub certificate: Vec<u8>,
    /// Contains the ultra-secret private key used to decode communications.
    pub private_key: Vec<u8>,
}
