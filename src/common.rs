use ascii::{AsciiStr, AsciiString};
use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

/// Status code of a request or response.
#[derive(Eq, PartialEq, Copy, Clone, Debug, Ord, PartialOrd)]
pub struct StatusCode(pub u16);

impl StatusCode {
    /// Returns the default reason phrase for this status code.
    /// For example the status code 404 corresponds to "Not Found".
    pub fn default_reason_phrase(&self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            103 => "Early Hints",

            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            208 => "Already Reported",
            226 => "IM Used",

            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",

            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            421 => "Misdirected Request",
            422 => "Unprocessable Entity",
            423 => "Locked",
            424 => "Failed Dependency",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",

            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",
            _ => "Unknown",
        }
    }
}

impl From<i8> for StatusCode {
    fn from(in_code: i8) -> StatusCode {
        StatusCode(in_code as u16)
    }
}

impl From<u8> for StatusCode {
    fn from(in_code: u8) -> StatusCode {
        StatusCode(in_code as u16)
    }
}

impl From<i16> for StatusCode {
    fn from(in_code: i16) -> StatusCode {
        StatusCode(in_code as u16)
    }
}

impl From<u16> for StatusCode {
    fn from(in_code: u16) -> StatusCode {
        StatusCode(in_code)
    }
}

impl From<i32> for StatusCode {
    fn from(in_code: i32) -> StatusCode {
        StatusCode(in_code as u16)
    }
}

impl From<u32> for StatusCode {
    fn from(in_code: u32) -> StatusCode {
        StatusCode(in_code as u16)
    }
}

impl AsRef<u16> for StatusCode {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl PartialEq<u16> for StatusCode {
    fn eq(&self, other: &u16) -> bool {
        &self.0 == other
    }
}

impl PartialEq<StatusCode> for u16 {
    fn eq(&self, other: &StatusCode) -> bool {
        self == &other.0
    }
}

impl PartialOrd<u16> for StatusCode {
    fn partial_cmp(&self, other: &u16) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialOrd<StatusCode> for u16 {
    fn partial_cmp(&self, other: &StatusCode) -> Option<Ordering> {
        self.partial_cmp(&other.0)
    }
}

/// Header parsing error.
#[derive(Debug)]
pub enum HeaderError
{
    /// Protocol violation reason.
    ProtocolViolation(String),
}

impl fmt::Display for HeaderError
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result 
    {
        match self
        {
            Self::ProtocolViolation(errmsg) => 
                write!(f, "protocol violation: {}", errmsg)
        }
    }
}


/// Represents a HTTP header.
#[derive(Debug, Clone)]
pub struct Header
{
    pub field: HeaderField,
    pub value: HeaderFieldValue,
}

impl Header 
{
    /// Builds a `Header` from two two `&[u8]`s.
    ///
    /// Example:
    ///
    /// ```ignore
    /// let header = tiny_http_fork::Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap();
    /// ```
    #[allow(clippy::result_unit_err)]
    pub 
    fn from_bytes<B1, B2>(header: B1, value: B2) -> Result<Self, HeaderError>
    where
        B1: AsRef<[u8]>,
        B2: AsRef<[u8]>,
    {
        let header = HeaderField::try_from(header.as_ref())?;

        let value = HeaderFieldValue::from_slice(&header, value)?;

        return Ok( 
            Header{ field: header, value: value } 
        );
    }

    /// Builds a `Header` from two two `&str`s.
    ///
    /// Example:
    ///
    /// ```ignore
    /// let header = tiny_http_fork::Header::from_str("Content-Type", "text/plain").unwrap();
    /// ```
    pub 
    fn from_str<S1, S2>(header: S1, value: S2) -> Result<Self, HeaderError>
    where
        S1: AsRef<str>,
        S2: AsRef<str>
    {
        Self::from_bytes(header.as_ref(), value.as_ref())
    }
}

impl TryFrom<String> for Header
{
    type Error = HeaderError;

    fn try_from(value: String) -> Result<Self, Self::Error> 
    {
        return Self::try_from(value.as_str());
    }
}

impl TryFrom<&str> for Header
{
    type Error = HeaderError;

    fn try_from(input: &str) -> Result<Self, Self::Error> 
    {
        let mut elems = input.splitn(2, ':');
        let field = elems.next().ok_or(HeaderError::ProtocolViolation("no key val present".into()))?;
        let value = elems.next().ok_or(HeaderError::ProtocolViolation("no val val present".into()))?;
        
        return Self::from_bytes(field, value);
    }
}

impl FromStr for Header 
{
    type Err = HeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> 
    {
        Self::try_from(s)
    }
}

impl Display for Header 
{
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), fmt::Error> 
    {
        write!(formatter, "{}: {}", self.field, self.value.as_str())
    }
}

/// A [HeaderFieldValueAscii] which does not support UTF-8 in headers.
#[cfg(not(feature = "allow_utf8_headers"))]
pub type HeaderFieldValue = HeaderFieldValueAscii;

/// A [HeaderFieldValueUtf] which does not support UTF-8 in headers.
#[cfg(feature = "allow_utf8_headers")]
pub type HeaderFieldValue = HeaderFieldValueUtf;

#[cfg(feature = "allow_utf8_headers")]
pub mod mod_header_value_utf
{
    use std::{collections::HashSet, sync::{LazyLock, OnceLock}};

    use super::*;

    const NON_UTF8_HEADERS: &'static [&'static str] = 
    &[
        "A-IM",
        "Age",
        "Accept",
        "Accept-Charset",
        "Accept-Datetime",
        "Accept-Encoding",
        "Accept-Language",
        "Access-Control-Request-Method",
        "Access-Control-Allow-Origin",
        "Authorization",
        "Cache-Control",
        "Connection",
        "Content-Encoding",
        "Content-Length",
        "Content-MD5",
        "Content-Type",
        "Cookie",
        "Date",
        "ETag",
        "Expect",
        "Forwarded",
        "Host",
        "From",
        "HTTP2-Settings",
        "If-Match",
        "If-None-Match",
        "If-Range",
        "If-Unmodified-Since",
        "Max-Forwards",
        "Pragma",
        "Proxy-Authorization",
        "Referer",
        "Server",
        "Set-Cookie",
        "Transfer-Encoding",
        "User-Agent",
        "Upgrade",
        "X-Forwarded-Host",
        "X-Backend-Server",
        "X-Requested-With",
        "X-Forwarded-Proto",
        "X-HTTP-Method-Override",
        "X-Att-Deviceid",
        "X-Cache-Info",
        "Vary"
    ];

    static NON_UTF8_HEADERS_SET: LazyLock<HashSet<&'static str>> = 
        LazyLock::new(|| NON_UTF8_HEADERS.iter().map(|s| *s).collect());

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct HeaderFieldValueUtf(String);

    impl AsRef<str> for HeaderFieldValueUtf
    {
        fn as_ref(&self) -> &str 
        {
            &self.0
        }
    }

    impl HeaderFieldValueUtf
    {
        pub(crate)
        fn from_slice<V>(field: &HeaderField, value: V) -> Result<Self, HeaderError>
        where V: AsRef<[u8]>
        {
            let val_str = 
                str::from_utf8(value.as_ref()).map_err(|e| HeaderError::ProtocolViolation(e.to_string()))?;

            Self::from_str(field, val_str)
        }

        pub(crate) 
        fn from_str(field: &HeaderField, value: &str) -> Result<Self, HeaderError>
        {
            let value_trimmed = value.trim();

            // reject values containing 0x0D, 0x0A or 0x00,
            // reject field names containing anything outside the RFC 9110 token set:
            //   Tokens are short textual identifiers that do not include whitespace or delimiters
            // Alphanumeric characters: U+0041 'A' ..= U+005A 'Z', or U+0061 'a' ..= U+007A 'z', or
            //    U+0030 '0' ..= U+0039 '9'.
            // OR
            // The following special characters: U+0021 ..= U+002F ! " # $ % & ' ( ) * + , - . /, or
            //    U+003A ..= U+0040 : ; < = > ? @, or U+005B ..= U+0060 [ \ ] ^ _ `, or
            //    U+007B ..= U+007E { | } ~

            // don't allow uncode in the base headers
            let res = 
                if NON_UTF8_HEADERS_SET.contains(field.as_str().as_str()) == true
                {
                    value_trimmed
                        .chars()
                        .all(
                            |ch| 
                            ch.is_ascii_alphanumeric() == true || ch.is_ascii_punctuation() == true ||
                            ch == ' ' 
                        )
                }
                else
                {
                    value_trimmed
                        .chars()
                        .all(
                            |ch| 
                            ch.is_alphanumeric() == true || ch.is_ascii_punctuation() == true ||
                            ch == ' '
                        )
                };

            
            if res == false
            {
                return Err(
                    HeaderError::ProtocolViolation(format!("header value contains invalid chars"))
                );
            }

            return Ok(Self(value_trimmed.to_string()));
        }

        pub 
        fn as_str(&self) -> &str
        {
            &self.0
        }
    }

    impl Display for HeaderFieldValueUtf 
    {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), fmt::Error> 
        {
            write!(formatter, "{}", self.0.as_str())
        }
    }
}

#[cfg(feature = "allow_utf8_headers")]
pub use self::mod_header_value_utf::HeaderFieldValueUtf;

#[cfg(not(feature = "allow_utf8_headers"))]
pub mod mod_header_value_ascii
{
    use super::*;

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct HeaderFieldValueAscii(AsciiString);

    impl AsRef<AsciiStr> for HeaderFieldValueAscii
    {
        fn as_ref(&self) -> &AsciiStr 
        {
            &self.0
        }
    }

    impl HeaderFieldValueAscii
    { 
        pub(crate)
        fn from_slice<V>(field: &HeaderField, value: V) -> Result<Self, HeaderError>
        where V: AsRef<[u8]>
        {
            let val_str = 
                AsciiStr::from_ascii(&value).map_err(|e| HeaderError::ProtocolViolation(e.to_string()))?;

            Self::from_str(field, val_str)
        }

        pub(crate)
        fn from_str(_field: &HeaderField, value: &AsciiStr) -> Result<Self, HeaderError>
        {
            let value_trimmed = value.trim();

            // reject values containing 0x0D, 0x0A or 0x00,
            // reject field names containing anything outside the RFC 9110 token set:
            //   Tokens are short textual identifiers that do not include whitespace or delimiters
            // Alphanumeric characters: U+0041 'A' ..= U+005A 'Z', or U+0061 'a' ..= U+007A 'z', or
            //    U+0030 '0' ..= U+0039 '9'.
            // OR
            // The following special characters: U+0021 ..= U+002F ! " # $ % & ' ( ) * + , - . /, or
            //    U+003A ..= U+0040 : ; < = > ? @, or U+005B ..= U+0060 [ \ ] ^ _ `, or
            //    U+007B ..= U+007E { | } ~
            if false == 
                value_trimmed.as_bytes()
                    .iter()
                    .all(|ch| ch.is_ascii_alphanumeric() == true || ch.is_ascii_punctuation() == true ||
                        *ch == b' ')
            {
                return Err(HeaderError::ProtocolViolation(format!("header value contains invalid chars")));
            }

            return Ok(Self(value_trimmed.to_ascii_string()));
        }

        pub 
        fn as_str(&self) -> &str
        {
            self.0.as_str()
        }
    }

    impl Display for HeaderFieldValueAscii 
    {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), fmt::Error> 
        {
            write!(formatter, "{}", self.0.as_str())
        }
    }
}

#[cfg(not(feature = "allow_utf8_headers"))]
pub use self::mod_header_value_ascii::HeaderFieldValueAscii;

/// Field of a header (eg. `Content-Type`, `Content-Length`, etc.)
///
/// Comparison between two `HeaderField`s ignores case.
#[derive(Debug, Clone, Eq)]
pub struct HeaderField(AsciiString);

impl HeaderField 
{ 
    fn from_str(key: &AsciiStr) -> Result<Self, HeaderError>
    {
            
        // reject values containing 0x0D, 0x0A or 0x00,
        // reject field names containing anything outside the RFC 9110 token set:
        //   Tokens are short textual identifiers that do not include whitespace or delimiters
        //    US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}").
        // - Alphanumeric characters: U+0041 'A' ..= U+005A 'Z', or U+0061 'a' ..= U+007A 'z', or
        //    U+0030 '0' ..= U+0039 '9'. or - or _

        if false ==
            key.as_str().chars()
                .all(|ch| 
                    ch.is_ascii_alphanumeric() == true || ch == '-' || ch == '_'
                ) 
        {
            return Err(HeaderError::ProtocolViolation("header key value contains invalid chars".into()));
        }

        return Ok(HeaderField(key.to_ascii_string()));
    }

    pub 
    fn as_str(&self) -> &AsciiStr 
    {
        &self.0
    }

    pub 
    fn equiv(&self, other: &'static str) -> bool 
    {
        other.eq_ignore_ascii_case(self.as_str().as_str())
    }
}

impl TryFrom<Vec<u8>> for HeaderField
{
    type Error = HeaderError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> 
    {
        let val_str = 
            AsciiStr::from_ascii(&value).map_err(|e| HeaderError::ProtocolViolation(e.to_string()))?;

        return Self::from_str(val_str);
    }
}

impl TryFrom<&[u8]> for HeaderField
{
    type Error = HeaderError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> 
    {
        let val_str = 
            AsciiStr::from_ascii(value).map_err(|e| HeaderError::ProtocolViolation(e.to_string()))?;

        return Self::from_str(val_str);
    }
}

impl TryFrom<&str> for HeaderField
{
    type Error = HeaderError;

    fn try_from(value: &str) -> Result<Self, Self::Error> 
    {
        let val_str = 
            AsciiStr::from_ascii(value).map_err(|e| HeaderError::ProtocolViolation(e.to_string()))?;

        Self::from_str(val_str)
    }
}

impl TryFrom<String> for HeaderField
{
    type Error = HeaderError;

    fn try_from(value: String) -> Result<Self, Self::Error> 
    {
        let val_str = 
            AsciiStr::from_ascii(&value).map_err(|e| HeaderError::ProtocolViolation(e.to_string()))?;

        Self::from_str(val_str)
    }
}


impl FromStr for HeaderField 
{
    type Err = HeaderError;

    fn from_str(s: &str) -> Result<Self, Self::Err> 
    {
        HeaderField::try_from(s)
    }
}
    

impl Display for HeaderField 
{
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), fmt::Error> 
    {
        write!(formatter, "{}", self.0.as_str())
    }
}

impl PartialEq for HeaderField 
{
    fn eq(&self, other: &HeaderField) -> bool 
    {
        let self_str: &str = self.as_str().as_ref();
        let other_str = other.as_str().as_ref();
        self_str.eq_ignore_ascii_case(other_str)
    }
}

/// HTTP request methods
///
/// As per [RFC 7231](https://tools.ietf.org/html/rfc7231#section-4.1) and
/// [RFC 5789](https://tools.ietf.org/html/rfc5789)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`
    Get,

    /// `HEAD`
    Head,

    /// `POST`
    Post,

    /// `PUT`
    Put,

    /// `DELETE`
    Delete,

    /// `CONNECT`
    Connect,

    /// `OPTIONS`
    Options,

    /// `TRACE`
    Trace,

    /// `PATCH`
    Patch,

    /// Request methods not standardized by the IETF
    NonStandard(AsciiString),
}

impl Method {
    pub fn as_str(&self) -> &str {
        match *self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Connect => "CONNECT",
            Method::Options => "OPTIONS",
            Method::Trace => "TRACE",
            Method::Patch => "PATCH",
            Method::NonStandard(ref s) => s.as_str(),
        }
    }
}

impl FromStr for Method {
    type Err = ();

    fn from_str(s: &str) -> Result<Method, ()> {
        Ok(match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "CONNECT" => Method::Connect,
            "OPTIONS" => Method::Options,
            "TRACE" => Method::Trace,
            "PATCH" => Method::Patch,
            s => {
                let ascii_string = AsciiString::from_ascii(s).map_err(|_| ())?;
                Method::NonStandard(ascii_string)
            }
        })
    }
}

impl Display for Method {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(formatter, "{}", self.as_str())
    }
}

/// HTTP version (usually 1.0 or 1.1).
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HTTPVersion(pub u8, pub u8);

impl Display for HTTPVersion {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(formatter, "{}.{}", self.0, self.1)
    }
}

impl Ord for HTTPVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let HTTPVersion(my_major, my_minor) = *self;
        let HTTPVersion(other_major, other_minor) = *other;

        if my_major != other_major {
            return my_major.cmp(&other_major);
        }

        my_minor.cmp(&other_minor)
    }
}

impl PartialOrd for HTTPVersion {
    fn partial_cmp(&self, other: &HTTPVersion) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<(u8, u8)> for HTTPVersion {
    fn eq(&self, &(major, minor): &(u8, u8)) -> bool {
        self.eq(&HTTPVersion(major, minor))
    }
}

impl PartialEq<HTTPVersion> for (u8, u8) {
    fn eq(&self, other: &HTTPVersion) -> bool {
        let &(major, minor) = self;
        HTTPVersion(major, minor).eq(other)
    }
}

impl PartialOrd<(u8, u8)> for HTTPVersion {
    fn partial_cmp(&self, &(major, minor): &(u8, u8)) -> Option<Ordering> {
        self.partial_cmp(&HTTPVersion(major, minor))
    }
}

impl PartialOrd<HTTPVersion> for (u8, u8) {
    fn partial_cmp(&self, other: &HTTPVersion) -> Option<Ordering> {
        let &(major, minor) = self;
        HTTPVersion(major, minor).partial_cmp(other)
    }
}

impl From<(u8, u8)> for HTTPVersion {
    fn from((major, minor): (u8, u8)) -> HTTPVersion {
        HTTPVersion(major, minor)
    }
}

#[cfg(test)]
mod test {
    use super::Header;
    use httpdate::HttpDate;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_parse_header() {
        let header: Header = "Content-Type: text/html".parse().unwrap();

        assert!(header.field.equiv(&"content-type"));
        assert!(header.value.as_str() == "text/html");

        assert!("hello world".parse::<Header>().is_err());
    }

    #[test]
    fn formats_date_correctly() {
        let http_date = HttpDate::from(SystemTime::UNIX_EPOCH + Duration::from_secs(420895020));

        assert_eq!(http_date.to_string(), "Wed, 04 May 1983 11:17:00 GMT")
    }

    #[test]
    fn test_parse_header_with_doublecolon() {
        let header: Header = "Time: 20: 34".parse().unwrap();

        assert!(header.field.equiv(&"time"));
        assert!(header.value.as_str() == "20: 34");
    }

    // This tests reslstance to RUSTSEC-2020-0031: "HTTP Request smuggling
    // through malformed Transfer Encoding headers"
    // (https://rustsec.org/advisories/RUSTSEC-2020-0031.html).
    #[test]
    fn test_strict_headers() 
    {
        assert!("Transfer-Encoding : chunked".parse::<Header>().is_err());
        assert!(" Transfer-Encoding: chunked".parse::<Header>().is_err());
        assert!("Transfer Encoding: chunked".parse::<Header>().is_err());
        assert!(" Transfer\tEncoding : chunked".parse::<Header>().is_err());
        assert!("Transfer-Encoding: chunked".parse::<Header>().is_ok());
        assert!("Transfer-Encoding: chunked ".parse::<Header>().is_ok());
        assert!("Transfer-Encoding:   chunked ".parse::<Header>().is_ok());
    }

    #[test]
    fn test_header_str()
    {
        Header::from_bytes("Content-Type", "text/plain; charset=UTF-8").unwrap();
        assert_eq!(Header::from_bytes("Content-Type", "text/plain; \x0acharset=UTF-8").is_err(), true);
        assert_eq!(Header::from_bytes("Content-Type", "text/plain; \x0dcharset=UTF-8").is_err(), true);
        assert_eq!(Header::from_bytes("Content-Type", "text/plain; charset=UTF-8\x00").is_err(), true);
        assert_eq!(Header::from_bytes("Content-Type", "text/plain; \x00charset=UTF-8").is_err(), true);
        assert_eq!(Header::from_bytes("Cont'ent-Type", "text/plain; charset=UTF-8").is_err(), true);
        assert_eq!(Header::from_bytes("Content@Type", "text/plain; charset=UTF-8").is_err(), true);
    }

    #[cfg(not(feature = "allow_utf8_headers"))]
    #[test]
    fn test_header_str_utf()
    {
        assert_eq!(Header::from_bytes("Auth-Custom-Type", "佳波").is_err(), true);
        assert_eq!(Header::from_bytes("Auth-Custom-Type", "Kanami").is_err(), false);
        assert_eq!(Header::from_bytes("Content-Type", "text/plain; charset=UTF-8; 由佳").is_err(), true);
    }

    #[cfg(feature = "allow_utf8_headers")]
    #[test]
    fn test_header_str_utf()
    {
        assert_eq!(Header::from_bytes("Auth-Custom-Type", "佳波").is_err(), false);
        assert_eq!(Header::from_bytes("Auth-Custom-Type", "Kanami").is_err(), false);
        assert_eq!(Header::from_bytes("Content-Type", "text/plain; charset=UTF-8; 由佳").is_err(), true);
    }
}
