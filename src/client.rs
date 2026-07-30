use ascii::AsciiString;

use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{BufReader, BufWriter, ErrorKind, Read};

use std::net::SocketAddr;
use std::str::FromStr;

use crate::common::{HTTPVersion, Method};
use crate::util::RefinedTcpStream;
use crate::util::{SequentialReader, SequentialReaderBuilder, SequentialWriterBuilder};
use crate::Request;

/// A ClientConnection is an object that will store a socket to a client
/// and return Request objects.
pub struct ClientConnection {
    // address of the client
    remote_addr: IoResult<Option<SocketAddr>>,

    // sequence of Readers to the stream, so that the data is not read in
    //  the wrong order
    source: SequentialReaderBuilder<BufReader<RefinedTcpStream>>,

    // sequence of Writers to the stream, to avoid writing response #2 before
    //  response #1
    sink: SequentialWriterBuilder<BufWriter<RefinedTcpStream>>,

    // Reader to read the next header from
    next_header_source: SequentialReader<BufReader<RefinedTcpStream>>,

    // set to true if we know that the previous request is the last one
    no_more_requests: bool,

    // true if the connection goes through SSL
    secure: bool,
}

/// Error that can happen when reading a request.
#[derive(Debug)]
enum ReadError {
    WrongRequestLine,
    WrongHeader(HTTPVersion),
    /// the client sent an unrecognized `Expect` header
    ExpectationFailed(HTTPVersion),
    ReadIoError(IoError),
}

impl ClientConnection {
    /// Creates a new `ClientConnection` that takes ownership of the `TcpStream`.
    pub fn new(
        write_socket: RefinedTcpStream,
        mut read_socket: RefinedTcpStream,
    ) -> ClientConnection {
        let remote_addr = read_socket.peer_addr();
        let secure = read_socket.secure();

        let mut source = SequentialReaderBuilder::new(BufReader::with_capacity(1024, read_socket));
        let first_header = source.next().unwrap();

        ClientConnection {
            source,
            sink: SequentialWriterBuilder::new(BufWriter::with_capacity(1024, write_socket)),
            remote_addr,
            next_header_source: first_header,
            no_more_requests: false,
            secure,
        }
    }

    /// true if the connection is HTTPS
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Reads the next line from self.next_header_source.
    ///
    /// Reads until `CRLF` is reached. The next read will start
    ///  at the first byte of the new line.
    /// 
    /// CVE-2026-66753 fixed
    fn read_next_line(&mut self) -> Result<AsciiString, ReadError> 
    {
        let mut buf = Vec::new();
        let mut rn = [0_u8; 2];
        let mut rn_p = 0;
        const RNC: u16 = u16::from_le_bytes([b'\r', b'\n']);

        
        loop 
        {
            let cur_byte = 
                self.next_header_source.by_ref().bytes().next()
                    .ok_or_else(||
                       ReadError::ReadIoError(IoError::new(ErrorKind::ConnectionAborted, "Unexpected EOF"))
                    )?
                    .map_err(|e|
                        ReadError::ReadIoError(e)
                    )?;

            match rn_p
            {
                0 => 
                {
                    if cur_byte != b'\r' && cur_byte != b'\n'
                    { // most times true
                        buf.push(cur_byte);
                    }
                    else
                    {
                        rn[rn_p] = cur_byte;
                        rn_p += 1;
                    }
                },
                _ =>
                {
                    rn[rn_p] = cur_byte;

                    if u16::from_le_bytes(rn) != RNC
                    {
                        // error
                        return Err(ReadError::WrongRequestLine);
                    }

                    return
                        AsciiString::from_ascii(buf)
                            .map_err(|_| ReadError::ReadIoError(IoError::new(ErrorKind::InvalidInput, "Header is not in ASCII")));
                }
            }
        }
    }

    /// Reads a request from the stream.
    /// Blocks until the header has been read.
    fn read(&mut self) -> Result<Request, ReadError> {
        let (method, path, version, headers) = {
            // reading the request line
            let (method, path, version) = {
                let line = self.read_next_line()?;

                parse_request_line(
                    line.as_str().trim(), // TODO: remove this conversion
                )?
            };

            // getting all headers
            let headers = 
                {
                    let mut headers = Vec::new();
                    loop 
                    {
                        let line = self.read_next_line()?;

                        if line.is_empty() {
                            break;
                        };
                        headers.push(match FromStr::from_str(line.as_str().trim()) {
                            // TODO: remove this conversion
                            Ok(h) => h,
                            _ => return Err(ReadError::WrongHeader(version)),
                        });
                    }

                    headers
                };

            (method, path, version, headers)
        };

        // building the writer for the request
        let writer = self.sink.next().unwrap();

        // follow-up for next potential request
        let mut data_source = self.source.next().unwrap();
        std::mem::swap(&mut self.next_header_source, &mut data_source);

        // fix https://github.com/tiny-http/tiny-http/pull/285
        let remote_addr = 
            self.remote_addr.as_ref()
                .map_err(|e| ReadError::ReadIoError(IoError::from(e.kind())))
                .map(|addr| *addr)?;

        // building the next reader
        let request = 
            crate::request::new_request(
                self.secure,
                method,
                path,
                version.clone(),
                headers,
                remote_addr,
                data_source,
                writer,
            )
            .map_err(|e| 
                {
                    use crate::request;
                    match e 
                    {
                        request::RequestCreationError::ProtocolViolation => 
                            ReadError::WrongRequestLine, // 400
                        request::RequestCreationError::CreationIoError(e) => 
                            ReadError::ReadIoError(e),
                        request::RequestCreationError::ExpectationFailed => 
                        {
                            ReadError::ExpectationFailed(version)
                        }
                    }
                }
            )?;

        // return the request
        Ok(request)
    }
}

impl Iterator for ClientConnection {
    type Item = Request;

    /// Blocks until the next Request is available.
    /// Returns None when no new Requests will come from the client.
    fn next(&mut self) -> Option<Request> {
        use crate::{Response, StatusCode};

        // the client sent a "connection: close" header in this previous request
        //  or is using HTTP 1.0, meaning that no new request will come
        if self.no_more_requests {
            return None;
        }

        loop {
            let rq = match self.read() {
                Err(ReadError::WrongRequestLine) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(400));
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None; // we don't know where the next request would start,
                                 // se we have to close
                }

                Err(ReadError::WrongHeader(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(400));
                    response.raw_print(writer, ver, &[], false, None).ok();
                    return None; // we don't know where the next request would start,
                                 // se we have to close
                }

                Err(ReadError::ReadIoError(ref err)) if err.kind() == ErrorKind::TimedOut => {
                    // request timeout
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(408));
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None; // closing the connection
                }

                Err(ReadError::ExpectationFailed(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(417));
                    response.raw_print(writer, ver, &[], true, None).ok();
                    return None; // TODO: should be recoverable, but needs handling in case of body
                }

                Err(ReadError::ReadIoError(_)) => return None,

                Ok(rq) => rq,
            };

            // checking HTTP version
            if *rq.http_version() > (1, 1) {
                let writer = self.sink.next().unwrap();
                let response = Response::from_string(
                    "This server only supports HTTP versions 1.0 and 1.1".to_owned(),
                )
                .with_status_code(StatusCode(505));
                response
                    .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                    .ok();
                continue;
            }

            // updating the status of the connection
            let connection_header = rq
                .headers()
                .iter()
                .find(|h| h.field.equiv("Connection"))
                .map(|h| h.value.as_str());

            let lowercase = connection_header.map(|h| h.to_ascii_lowercase());

            match lowercase {
                Some(ref val) if val.contains("close") => self.no_more_requests = true,
                Some(ref val) if val.contains("upgrade") => self.no_more_requests = true,
                Some(ref val)
                    if !val.contains("keep-alive") && *rq.http_version() == HTTPVersion(1, 0) =>
                {
                    self.no_more_requests = true
                }
                None if *rq.http_version() == HTTPVersion(1, 0) => self.no_more_requests = true,
                _ => (),
            };

            // returning the request
            return Some(rq);
        }
    }
}

/// Parses a "HTTP/1.1" string.
fn parse_http_version(version: &str) -> Result<HTTPVersion, ReadError> {
    let (major, minor) = match version {
        "HTTP/0.9" => (0, 9),
        "HTTP/1.0" => (1, 0),
        "HTTP/1.1" => (1, 1),
        "HTTP/2.0" => (2, 0),
        "HTTP/3.0" => (3, 0),
        _ => return Err(ReadError::WrongRequestLine),
    };

    Ok(HTTPVersion(major, minor))
}

/// Parses the request line of the request.
/// eg. GET / HTTP/1.1
fn parse_request_line(line: &str) -> Result<(Method, String, HTTPVersion), ReadError> {
    let mut parts = line.split(' ');

    let method = parts.next().and_then(|w| w.parse().ok());
    let path = parts.next().map(ToOwned::to_owned);
    let version = parts.next().and_then(|w| parse_http_version(w).ok());

    method
        .and_then(|method| Some((method, path?, version?)))
        .ok_or(ReadError::WrongRequestLine)
}

#[cfg(test)]
mod test 
{
    use std::{iter::Peekable, str::Bytes};

use super::*;

    #[test]
    fn test_parse_request_line() 
    {
        let (method, path, ver) = super::parse_request_line("GET /hello HTTP/1.1").unwrap();

        assert!(method == crate::Method::Get);
        assert!(path == "/hello");
        assert!(ver == crate::common::HTTPVersion(1, 1));

        assert!(super::parse_request_line("GET /hello").is_err());
        assert!(super::parse_request_line("qsd qsd qsd").is_err());
    }

    fn new_readline(line: &str) -> Result<Vec<String>, ReadError> 
    {   
        let mut line_itr = line.bytes().peekable();
        let mut res = Vec::with_capacity(6);

        while let Some(_) = line_itr.peek()
        {
            res.push(new_readline_int(&mut line_itr).map(|v| v.as_str().to_string())?);
        }

        return Ok(res);
    }   

    fn new_readline_int(line_itr: &mut Peekable<Bytes<'_>>) -> Result<AsciiString, ReadError> 
    {
        let mut buf = Vec::new();
        let mut rn = [0_u8; 2];
        let mut rn_p = 0;
        const RNC: u16 = u16::from_le_bytes([b'\r', b'\n']);

        
        loop 
        {
            let cur_byte = 
                line_itr.next()
                    .ok_or_else(||
                       ReadError::ReadIoError(IoError::new(ErrorKind::ConnectionAborted, "Unexpected EOF"))
                    )?;

            match rn_p
            {
                0 => 
                {
                    if cur_byte != b'\r' && cur_byte != b'\n'
                    { // most times true
                        buf.push(cur_byte);
                    }
                    else
                    {
                        rn[rn_p] = cur_byte;
                        rn_p += 1;
                    }
                },
                _ =>
                {
                    rn[rn_p] = cur_byte;

                    if u16::from_le_bytes(rn) != RNC
                    {
                        // error
                        return Err(ReadError::WrongRequestLine);
                    }

                    return
                        AsciiString::from_ascii(buf)
                            .map_err(|_| ReadError::ReadIoError(IoError::new(ErrorKind::InvalidInput, "Header is not in ASCII")));
                }
            }
        }
    }

    #[test]
    fn test_new_readline()
    {
        let vals = new_readline("Server: tiny-http (Rust)\r\n").unwrap();
        assert_eq!(vals.len(), 1);
        assert_eq!(vals.contains(&"Server: tiny-http (Rust)".into()), true);

        let vals = new_readline("Server: tiny-http (Rust)\r\nContent-Type: text/plain; charset=UTF-8\r\n").unwrap();
        assert_eq!(vals.len(), 2);
        assert_eq!(vals.contains(&"Server: tiny-http (Rust)".into()), true);
        assert_eq!(vals.contains(&"Content-Type: text/plain; charset=UTF-8".into()), true);

        let vals = new_readline("Server: tiny-http (Rust)\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n").unwrap();
        assert_eq!(vals.len(), 3);
        assert_eq!(vals.contains(&"Server: tiny-http (Rust)".into()), true);
        assert_eq!(vals.contains(&"Content-Type: text/plain; charset=UTF-8".into()), true);


        assert_eq!(new_readline("Server: tiny-http (Rust)\r\r\n").is_err(), true);
        assert_eq!(new_readline("Server: tiny-http (Rust)\n\r\n").is_err(), true);
        assert_eq!(new_readline("Server: tiny-http\n(Rust)\r\n").is_err(), true);
        assert_eq!(new_readline("GET / HTTP/1.1\r\nHost: x\r\nX-Test: aaa\nbbb\r\nConnection: close\r\n\r\n").is_err(), true);
    }
}
