//! A minimal `Tower` middleware layer for mitigating CSRF attacks.
//!
//! Examines the `Origin` or `Referer` header of incoming requests, and compares
//! it to the target `Host` and `URI`.
//!
//! ```
//! let (mock_service, _) = tower_test::mock::spawn::<http::Request<()>, ()>();
//! let csrf_proof_service = origin_check::OriginCheck::new(mock_service);
//! ```
//!
//! # IMPORTANT NOTES:
//!
//! This crate makes several assumptions that *must all be true for it to be a good
//! choice for you:*
//!
//! 1. Your site is accessed exclusively in "secure contexts", like over `https` or
//!    on `localhost`.
//! 2. State changes are *never performed* in response to `GET` or `HEAD` requests.
//!    Such requests are _always allowed_ by this service, regardless of CSRF
//!    indicators.
//! 3. All other requests _should fail_ if the hostname and port of the `Origin` or
//!    `Referer` does not _exactly_ match the `Host`. This means that you cannot,
//!    e.g., send POST requests from one subdomain to another, or from one port to
//!    another.
//! 4. Your users' browsers will set the `Origin` or `Referer` header on
//!    non-`GET`/-`HEAD` requests, when those requests are initiated by your site.
//!    In order to ensure this, be careful that the `Referrer-Policy` for your site
//!    is not set to `no-referrer`.
//!
//! You probably want to set `SameSite=Strict` or `SameSite=Lax` on any
//! authentication cookies, as additional protection against CSRF.
//!
//! You likely also want to set `X-Frame-Options: DENY` for your site by default,
//! to prevent clickjacking, which is a distinct but related problem to CSRF.
//!
//! # Features
//!
//! * `tower-layer`: optional, enabled by default. Adds an impl for `tower_layer::Layer`.

#![warn(missing_docs)]

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{method::Method, uri::Scheme, Request, Uri};
use pin_project::pin_project;
use tower::{BoxError, Service};

/// Tower middleware service that verifies that a request's origin matches the target host on
/// non-GET, non-HEAD requests.
#[derive(Debug, Clone)]
pub struct OriginCheck<S> {
    inner: S,
}

/// Error returned when the origin is not allowed.
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub enum OriginCheckError {
    /// The specified header is required, but was missing.
    MissingHeader(String),
    /// There were multiple headers when there should only have been one
    TooManyOfHeader(String, Vec<Vec<u8>>),
    /// This header was invalid (e.g. was not valid utf-8)
    InvalidHeader(Vec<u8>),
    /// The given string was not a valid URI, though it should have been
    InvalidUri(String),
    /// The specified origin did not match the host
    DisallowedOrigin(String),
}

/// Future type produced by the OriginCheck Service.
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
#[pin_project(project = ResponseFutureProj)]
pub enum ResponseFuture<F: Future> {
    /// The request can proceed as normal
    Ok(#[pin] F),
    /// The request failed an origin check
    Err(OriginCheckError),
}

impl<S> OriginCheck<S> {
    /// Create a new OriginCheck to wrap the given service.
    pub fn new(inner: S) -> OriginCheck<S> {
        OriginCheck { inner }
    }
}

impl fmt::Display for OriginCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OriginCheckError::*;
        let errstr = match self {
            MissingHeader(h) => format!("Missing header: {h}"),
            TooManyOfHeader(h, rs) => {
                let values: Vec<_> = rs
                    .iter()
                    .map(|bs| String::from_utf8_lossy(bs).into_owned())
                    .collect();
                format!("Too many instances of header {h}: {:?}", values)
            }
            InvalidHeader(r) => {
                format!("Invalid header: {}", String::from_utf8_lossy(r))
            }
            InvalidUri(u) => format!("Invalid uri: {u}"),
            DisallowedOrigin(r) => format!("Disallowed origin: {:?}", r),
        };
        write!(f, "Origin error: {}", errstr)
    }
}

impl std::error::Error for OriginCheckError {}

impl<F: Future<Output = Result<Response, Error>>, Response, Error: Into<BoxError>> Future
    for ResponseFuture<F>
{
    type Output = Result<Response, BoxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use Poll::{Pending, Ready};
        match self.project() {
            ResponseFutureProj::Ok(f) => match Future::poll(f, cx) {
                Ready(res) => Ready(res.map_err(Into::into)),
                Pending => Pending,
            },
            ResponseFutureProj::Err(e) => Ready(Err(Box::new(e.clone()))),
        }
    }
}

fn get_exactly_one_uri_header<B>(
    request: &Request<B>,
    label: &str,
) -> Result<Uri, OriginCheckError> {
    let headers = request.headers().get_all(label).iter().collect::<Vec<_>>();
    if headers.len() > 1 {
        let headers = headers.into_iter().map(|h| h.as_bytes().to_vec()).collect();
        return Err(OriginCheckError::TooManyOfHeader(
            label.to_string(),
            headers,
        ));
    }
    let header = match headers.get(0) {
        None => return Err(OriginCheckError::MissingHeader(label.to_string())),
        Some(r) => r,
    };
    let header_str = match header.to_str() {
        Ok(s) => s,
        Err(_) => return Err(OriginCheckError::InvalidHeader(header.as_bytes().to_vec())),
    };
    let uri = match header_str.parse::<Uri>() {
        Err(_) => {
            return Err(OriginCheckError::InvalidUri(header_str.to_string()));
        }
        Ok(r) => r,
    };
    Ok(uri)
}

fn potentially_trustworthy(uri: &Uri) -> bool {
    // https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy
    use std::str::FromStr;
    if uri.scheme() == Some(&Scheme::HTTPS) {
        // We don't accept wss:// or file:// schemes, because they seem sketchy in this context
        // (also I think they don't even parse as uris according to the `http` library)
        return true;
    }
    let host = match uri.host() {
        None => return false,
        Some(h) => h,
    };
    if ["localhost", "localhost."].contains(&host)
        || host.ends_with(".localhost")
        || host.ends_with(".localhost.")
    {
        return true;
    }
    if let Ok(i) = std::net::Ipv4Addr::from_str(host) {
        let local_net = cidr::Ipv4Cidr::from_str("127.0.0.0/8").unwrap();
        if local_net.contains(&i) {
            return true;
        }
    }

    let ip6_host = if host.starts_with('[') && host.ends_with(']') {
        host.strip_prefix('[').unwrap().strip_suffix(']').unwrap()
    } else {
        return false;
    };
    if let Ok(i) = std::net::Ipv6Addr::from_str(ip6_host) {
        let local_net = cidr::Ipv6Cidr::from_str("::1/128").unwrap();
        if local_net.contains(&i) {
            return true;
        }
    }

    false
}

fn validate_request<B>(request: &Request<B>) -> Result<(), OriginCheckError> {
    if [Method::GET, Method::HEAD].contains(request.method()) {
        return Ok(());
    }
    let origin = match get_exactly_one_uri_header(request, "Origin") {
        Err(OriginCheckError::MissingHeader(_)) => None,
        Err(e) => return Err(e),
        Ok(o) => Some(o),
    };
    let origin_or_referer = match origin {
        Some(o) => o,
        None => get_exactly_one_uri_header(request, "Referer")?,
    };

    // The host part of the URI can come from multiple places:
    //  - in HTTP 1, a `Host` header is required, which contains the hostname and port.
    //  - but also, the path can be an "absolute uri" including the target host. At least
    //      in HTTP 1.1, this is only for proxies, but must be handled by the server.
    //  - in HTTP/2, the Host header is optional, and instead encoded in the :authority
    //     pseudo-header. I believe that http services will then put this information in the `uri`
    //     field, or in the `Host` header, but I'm not confident that they're consistent about it.
    //
    //  So, we need to be able to get a host (and optional port) from *at least one* of these
    //  places. If we get it from multiple places, they must all match.

    let host_header_uri = get_exactly_one_uri_header(request, "Host");
    let (target_host, target_port) = match (host_header_uri, request.uri().host()) {
        (Ok(h), None) if h.host().is_some() => (h.host().unwrap().to_string(), h.port_u16()),
        (Ok(_), None) => return Err(OriginCheckError::MissingHeader("Host".to_string())),
        (Err(OriginCheckError::MissingHeader(_)), Some(u)) => {
            (u.to_string(), request.uri().port_u16())
        }
        (Err(e), _) => return Err(e),
        (Ok(h), Some(u)) if h.host() == Some(u) && h.port() == request.uri().port() => {
            (u.to_string(), h.port_u16())
        }
        (Ok(h), Some(u)) => {
            return Err(OriginCheckError::TooManyOfHeader(
                "Host".to_string(),
                vec![h.to_string().as_bytes().to_vec(), u.as_bytes().to_vec()],
            ))
        }
    };

    if origin_or_referer.host() == Some(&target_host)
        && origin_or_referer.port_u16() == target_port
        && potentially_trustworthy(&origin_or_referer)
    {
        Ok(())
    } else {
        Err(OriginCheckError::DisallowedOrigin(
            origin_or_referer.to_string(),
        ))
    }
}

impl<S: Service<Request<B>>, B> Service<Request<B>> for OriginCheck<S>
where
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        match validate_request(&request) {
            Ok(()) => ResponseFuture::Ok(self.inner.call(request)),
            Err(e) => ResponseFuture::Err(e),
        }
    }
}

#[cfg(feature = "tower-layer")]
/// A dummy layer type, allowing use of the OriginCheck as a `tower-layer::Layer`.
#[derive(Debug, Clone, Default)]
pub struct OriginCheckLayer {
    _priv: (),
}

#[cfg(feature = "tower-layer")]
impl<S> tower_layer::Layer<S> for OriginCheckLayer {
    type Service = OriginCheck<S>;

    fn layer(&self, service: S) -> Self::Service {
        OriginCheck::new(service)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use http::Request;
    #[test]
    fn get_request_always_allowed() {
        let req = Request::builder().uri("/foo").body("").unwrap();
        validate_request(&req).unwrap();
        let req = Request::builder()
            .uri("/foo")
            .method("POST")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());

        let req = Request::builder()
            .uri("https://google.com/foo")
            .method("GET")
            .body("")
            .unwrap();
        validate_request(&req).unwrap();
        let req = Request::builder()
            .uri("https://google.com/foo")
            .method("PUT")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn origin_header_suffices() {
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Origin", "https://google.com")
            .body("")
            .unwrap();
        validate_request(&req).unwrap();
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Origin", "https://foo.google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Origin", "http://google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "localhost")
            .header("Origin", "http://google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn referer_header_suffices() {
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Referer", "https://google.com")
            .body("")
            .unwrap();
        validate_request(&req).unwrap();
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Referer", "https://google.com/alsfdkj")
            .body("")
            .unwrap();
        validate_request(&req).unwrap();
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Referer", "https://google.com/askn?in=40")
            .body("")
            .unwrap();
        validate_request(&req).unwrap();
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Referer", "https://foo.google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Referer", "http://google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "localhost")
            .header("Referer", "http://google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn multiple_headers_fail() {
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Referer", "https://google.com")
            .header("Referer", "https://google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
        let req = Request::builder()
            .uri("/foo")
            .method("PUT")
            .header("Host", "google.com")
            .header("Origin", "https://google.com")
            .header("Origin", "https://google.com")
            .body("")
            .unwrap();
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn trustworthy_contexts() {
        assert!(!potentially_trustworthy(&"foo".parse().unwrap()));
        assert!(!potentially_trustworthy(&"foo:443".parse().unwrap()));
        assert!(!potentially_trustworthy(&"foo:123".parse().unwrap()));
        assert!(!potentially_trustworthy(&"http://foo".parse().unwrap()));
        assert!(potentially_trustworthy(&"127.0.0.1".parse().unwrap()));
        assert!(!potentially_trustworthy(&"128.0.0.1".parse().unwrap()));
        assert!(potentially_trustworthy(
            &"http://127.0.0.1".parse().unwrap()
        ));
        assert!(potentially_trustworthy(
            &"http://localhost.".parse().unwrap()
        ));
        assert!(potentially_trustworthy(
            &"http://dev.localhost".parse().unwrap()
        ));
        assert!(potentially_trustworthy(
            &"https://localhost".parse().unwrap()
        ));
        assert!(potentially_trustworthy(&"https://bar".parse().unwrap()));
        assert!(potentially_trustworthy(
            &"https://bar:8080".parse().unwrap()
        ));
        assert!(potentially_trustworthy(&"http://[::1]".parse().unwrap()));
    }
}
