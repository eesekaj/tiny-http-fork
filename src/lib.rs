//! # Simple usage
//!
//! ## Creating the server
//!
//! The easiest way to create a server is to call `Server::http()`.
//!
//! The `http()` function returns an `IoResult<Server>` which will return an error
//! in the case where the server creation fails (for example if the listening port is already
//! occupied).
//!
//! ```ignore
//! let server = tiny_http_fork::Server::http("0.0.0.0:0").unwrap();
//! ```
//!
//! A newly-created `Server` will immediately start listening for incoming connections and HTTP
//! requests.
//!
//! ## Receiving requests
//!
//! Calling `server.recv()` will block until the next request is available.
//! This function returns an `IoResult<Request>`, so you need to handle the possible errors.
//!
//! ```ignore
//! # let server = tiny_http_fork::Server::http("0.0.0.0:0").unwrap();
//!
//! loop {
//!     // blocks until the next request is received
//!     let request = match server.recv() {
//!         Ok(rq) => rq,
//!         Err(e) => { println!("error: {}", e); break }
//!     };
//!
//!     // do something with the request
//!     // ...
//! }
//! ```
//!
//! In a real-case scenario, you will probably want to spawn multiple worker tasks and call
//! `server.recv()` on all of them. Like this:
//!
//! ```ignore
//! # use std::sync::Arc;
//! # use std::thread;
//! # let server = tiny_http_fork::Server::http("0.0.0.0:0").unwrap();
//! let server = Arc::new(server);
//! let mut guards = Vec::with_capacity(4);
//!
//! for _ in (0 .. 4) {
//!     let server = server.clone();
//!
//!     let guard = thread::spawn(move || {
//!         loop {
//!             let rq = server.recv().unwrap();
//!
//!             // ...
//!         }
//!     });
//!
//!     guards.push(guard);
//! }
//! ```
//!
//! If you don't want to block, you can call `server.try_recv()` instead.
//!
//! ## Handling requests
//!
//! The `Request` object returned by `server.recv()` contains informations about the client's request.
//! The most useful methods are probably `request.method()` and `request.url()` which return
//! the requested method (`GET`, `POST`, etc.) and url.
//!
//! To handle a request, you need to create a `Response` object. See the docs of this object for
//! more infos. Here is an example of creating a `Response` from a file:
//!
//! ```ignore
//! # use std::fs::File;
//! # use std::path::Path;
//! let response = tiny_http_fork::Response::from_file(File::open(&Path::new("image.png")).unwrap());
//! ```
//!
//! All that remains to do is call `request.respond()`:
//!
//! ```ignore
//! # use std::fs::File;
//! # use std::path::Path;
//! # let server = tiny_http_fork::Server::http("0.0.0.0:0").unwrap();
//! # let request = server.recv().unwrap();
//! # let response = tiny_http_fork::Response::from_file(File::open(&Path::new("image.png")).unwrap());
//! let _ = request.respond(response);
//! ```
//#![forbid(unsafe_code)] // removed because an alarm code is required, will be returned  back when XIO-RS will be ready
#![deny(rust_2018_idioms)]
#![allow(clippy::match_like_matches_macro)]

mod client;
mod common;
mod connection;
mod log;
mod request;
mod response;
mod ssl;
mod test;
pub mod util;
pub mod config;

#[cfg(any(
    feature = "ssl-openssl",
    feature = "ssl-rustls",
    feature = "ssl-native-tls"
))]
use zeroize::Zeroizing;



use std::error::Error;
use std::io;
use std::io::Error as IoError;
use std::io::ErrorKind as IoErrorKind;
use std::io::Result as IoResult;
use std::net::ToSocketAddrs;
#[cfg(unix)]
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use client::ClientConnection;
use util::MessagesQueue;

pub use common::{HTTPVersion, Header, HeaderField, Method, StatusCode};
pub use connection::{ConfigListenAddr, ListenAddr, Listener};
pub use request::{ReadWrite, Request};
pub use response::{Response, ResponseBox};
pub use test::TestRequest;

use crate::config::ServerConfig;
use crate::config::SslConfig;
use crate::util::TaskPool;



#[cfg(not(any(
    feature = "ssl-openssl",
    feature = "ssl-rustls",
    feature = "ssl-native-tls"
)))]
type SslContext = ();
#[cfg(any(
    feature = "ssl-openssl",
    feature = "ssl-rustls",
    feature = "ssl-native-tls"
))]
type SslContext = ssl::SslContextImpl;

#[derive(Debug)]
pub struct SslContextWrap(Option<SslContext>);


impl SslContextWrap
{
    pub 
    fn build_ssl_capabilities(ssl_config: Option<SslConfig>) 
        -> Result<Self, Box<dyn Error + Send + Sync>>
    {
        // building the SSL capabilities
        let ssl: Option<SslContext> = 
            {
                match ssl_config 
                {
                    #[cfg(any(
                        feature = "ssl-openssl",
                        feature = "ssl-rustls",
                        feature = "ssl-native-tls"
                    ))]
                    Some(config) => 
                        Some(
                            SslContext::from_pem(config.certificate,
                            Zeroizing::new(config.private_key))?
                        ),
                    #[cfg(not(any(
                        feature = "ssl-openssl",
                        feature = "ssl-rustls",
                        feature = "ssl-native-tls"
                    )))]
                    Some(_) => 
                        return Err(
                            "Building a server with SSL requires enabling the `ssl` feature in tiny-http"
                                .into(),
                        ),
                    None => 
                        None,
                }
            };

        return Ok(Self(ssl));
    }
}

/// The main class of this library.
///
/// Destroying this object will immediately close the listening socket and the reading
///  part of all the client's connections. Requests that have already been returned by
///  the `recv()` function will not close and the responses will be transferred to the client.
#[derive(Debug)]
pub struct Server 
{
    // should be false as long as the server exists
    // when set to true, all the subtasks will close within a few hundreds ms
    close: Arc<AtomicBool>,

    // queue for messages received by child threads
    messages: Arc<MessagesQueue<Message>>,

    // result of TcpListener::local_addr()
    listening_addr: Option<ListenAddr>,
}

#[derive(Debug)]
pub enum Message 
{
    Error(IoError),
    NewRequest(Request),
}

impl From<IoError> for Message 
{
    fn from(e: IoError) -> Message 
    {
        Message::Error(e)
    }
}

impl From<Request> for Message 
{
    fn from(rq: Request) -> Message 
    {
        Message::NewRequest(rq)
    }
}

// this trait is to make sure that Server implements Share and Send
#[doc(hidden)]
trait MustBeShareDummy: Sync + Send {}
#[doc(hidden)]
impl MustBeShareDummy for Server {}

#[derive(Debug)]
pub struct IncomingRequests<'a> 
{
    server: &'a Server,
}


impl Server 
{
    /// Shortcut for a simple server on a specific address.
    #[inline]
    pub 
    fn http<A>(addr: A) -> Result<Server, Box<dyn Error + Send + Sync + 'static>>
    where
        A: ToSocketAddrs,
    {
        Server::new(
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

    /// Shortcut for an HTTPS server on a specific address.
    #[cfg(any(
        feature = "ssl-openssl",
        feature = "ssl-rustls",
        feature = "ssl-native-tls"
    ))]
    #[inline]
    pub fn https<A>(
        addr: A,
        config: SslConfig,
    ) -> Result<Server, Box<dyn Error + Send + Sync + 'static>>
    where
        A: ToSocketAddrs,
    {
        Server::new(
            ServerConfig 
            {
                addr: 
                    ConfigListenAddr::from_socket_addrs(addr)?,
                ssl: 
                    Some(config),
                min_threads: 
                    None,
                max_threads: 
                    None,
            }
        )
    }

    #[cfg(unix)]
    #[inline]
    /// Shortcut for a UNIX socket server at a specific path
    pub 
    fn http_unix<P: AsRef<Path>>(path: P) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> 
    {
        Server::new(
            ServerConfig 
            {
                addr: 
                    ConfigListenAddr::unix_from_path(path.as_ref()),
                ssl: 
                    None,
                min_threads: 
                    None,
                max_threads: 
                    None,
            }
        )
    }

    /// Builds a new server that listens on the specified address.
    pub 
    fn new(config: ServerConfig) -> Result<Server, Box<dyn Error + Send + Sync + 'static>> 
    {
        let (listener, la) = config.addr.bind()?;
        Self::from_listener(listener, la, config)
    }

    

    /// Accepts the incoming connection.
    /// 
    /// This function has visibility `pub` which is a part of effort to move from the 
    /// thread per client model, to POLL + task assignment.
    pub 
    fn accept_connection(server: &Listener, ssl: &SslContextWrap) -> Result<Option<ClientConnection>, IoError>
    {
        let (sock, _) = server.accept()?;

        use util::RefinedTcpStream;
        let (read_closable, write_closable) = 
            match ssl.0
            {
                None => 
                    RefinedTcpStream::new(sock),
                #[cfg(any(
                    feature = "ssl-openssl",
                    feature = "ssl-rustls",
                    feature = "ssl-native-tls"
                ))]
                Some(ref ssl) => 
                {
                    // trying to apply SSL over the connection
                    // if an error occurs, we just close the socket and resume listening
                    let Ok(sock) = ssl.accept(sock) 
                        else
                        {
                            return Ok(None);
                        };


                    RefinedTcpStream::new(sock)
                }
                #[cfg(not(any(
                    feature = "ssl-openssl",
                    feature = "ssl-rustls",
                    feature = "ssl-native-tls"
                )))]
                Some(ref _ssl) => 
                    unreachable!(),
            };

        return 
            Ok( Some(ClientConnection::new(write_closable, read_closable)) );
    }

    /// Initializes a thread for a freshly accepted client.
    /// 
    /// ToDo, replace the tasks_pool with polling of client socket + async without tokio
    pub 
    fn new_client(
        new_client: Result<Option<ClientConnection>, IoError>,
        inside_messages: &Arc<MessagesQueue<Message>>,
        tasks_pool: &TaskPool
    ) -> io::Result<()>
    {
        match new_client 
        {
            Ok(Some(client)) =>
            {
                let messages = inside_messages.clone();
                let mut client = Some(client);

                tasks_pool
                    .spawn(
                        Box::new(
                            move || 
                            {
                                if let Some(client) = client.take() 
                                {
                                    // Synchronization is needed for HTTPS requests to avoid a deadlock
                                    if client.secure() == true
                                    {
                                        let (sender, receiver) = mpsc::channel();
                                        for rq in client 
                                        {
                                            messages.push(rq.with_notify_sender(sender.clone()).into());
                                            receiver.recv().unwrap();
                                        }
                                    } 
                                    else 
                                    {
                                        for rq in client 
                                        {
                                            messages.push(rq.into());
                                        }
                                    }
                                }
                            }
                        )
                    )?;

                return Ok(());
            },
            Ok(None) => 
                return Ok(()),
            Err(ref e) if e.kind() == IoErrorKind::ConnectionAborted =>
            {
                // A non-fatal error.  Log it, and try to accept
                // a new connection.
                log::debug!("Error accepting new client: {}", e);

                return Ok(());
            },
            Err(e) => 
            {
                let kind = e.kind();
                log::error!("Error accepting new client: {}", e);
                inside_messages.push(e.into());

                return Err(IoError::new(kind, format!("new_client() accept() error")));
            }
        }
    }

    /// Builds a new server using the specified TCP listener.
    ///
    /// This is useful if you've constructed TcpListener using some less usual method
    /// such as from systemd. For other cases, you probably want the `new()` function.
    pub 
    fn from_listener<L: Into<Listener>>(listener: L, local_addr: ListenAddr, config: ServerConfig) 
        -> Result<Server, Box<dyn Error + Send + Sync + 'static>> 
    {
        let server = listener.into();
        // building the "close" variable
        let close_trigger = Arc::new(AtomicBool::new(false));

        // local addr does not work on OpenBSD
        //let local_addr: ListenAddr = config.addr.into();
        log::debug!("Server listening on {}", local_addr);

        // building the SSL capabilities
        let ssl= SslContextWrap::build_ssl_capabilities(config.ssl)?;

        // creating a task where server.accept() is continuously called
        // and ClientConnection objects are pushed in the messages queue
        let messages = MessagesQueue::with_capacity(8);

        let inside_close_trigger = close_trigger.clone();
        let inside_messages = messages.clone();
        
        // a tasks pool is used to dispatch the connections into threads
        let tasks_pool = util::TaskPool::new(config.min_threads, config.max_threads)?;

        thread::spawn(
            move || 
            {
                log::debug!("Running accept thread");

                while inside_close_trigger.load(Relaxed) == false
                {
                    let new_client = 
                        Self::accept_connection(&server, &ssl);

                    if let Err(_) = Self::new_client(new_client, &inside_messages, &tasks_pool)
                    {
                        break;
                    }
                }

                log::debug!("Terminating accept thread");
            }
        );

        // result
        return Ok(
            Server 
            {
                messages,
                close: 
                    close_trigger,
                listening_addr: 
                    Some(local_addr),
            }
        );
    }

    /// Returns an iterator for all the incoming requests.
    ///
    /// The iterator will return `None` if the server socket is shutdown.
    #[inline]
    pub 
    fn incoming_requests(&self) -> IncomingRequests<'_> 
    {
        IncomingRequests { server: self }
    }

    /// Returns the address the server is listening to.
    #[inline]
    pub 
    fn server_addr(&self) -> &ListenAddr 
    {
        self.listening_addr.as_ref().unwrap()
    }

    /// Returns the number of clients currently connected to the server.
    pub 
    fn num_connections(&self) -> usize 
    {
        unimplemented!()
        //self.requests_receiver.lock().len()
    }

    /// Blocks until an HTTP request has been submitted and returns it.
    pub 
    fn recv(&self) -> IoResult<Request> 
    {
        match self.messages.pop() 
        {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(rq),
            None => Err(IoError::new(IoErrorKind::Other, "thread unblocked")),
        }
    }

    /// Same as `recv()` but doesn't block longer than timeout
    pub 
    fn recv_timeout(&self, timeout: Duration) -> IoResult<Option<Request>> 
    {
        match self.messages.pop_timeout(timeout) 
        {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(Some(rq)),
            None => Ok(None),
        }
    }

    /// Same as `recv()` but doesn't block.
    pub 
    fn try_recv(&self) -> IoResult<Option<Request>> 
    {
        match self.messages.try_pop() 
        {
            Some(Message::Error(err)) => Err(err),
            Some(Message::NewRequest(rq)) => Ok(Some(rq)),
            None => Ok(None),
        }
    }

    /// Unblock thread stuck in recv() or incoming_requests().
    /// If there are several such threads, only one is unblocked.
    /// This method allows graceful shutdown of server.
    pub 
    fn unblock(&self) 
    {
        self.messages.unblock();
    }
}

impl Iterator for IncomingRequests<'_> 
{
    type Item = Request;
    
    fn next(&mut self) -> Option<Request> 
    {
        self.server.recv().ok()
    }
}

impl Drop for Server 
{
    fn drop(&mut self) 
    {
        self.close.store(true, Relaxed);
        // Connect briefly to ourselves to unblock the accept thread
        
        drop(self.listening_addr.take().unwrap());

    }
}
