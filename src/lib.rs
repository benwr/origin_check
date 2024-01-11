use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{method::Method, uri::Scheme, HeaderValue, Request, Uri};
use pin_project::pin_project;
use tower::{BoxError, Service};

/// Middleware that checks that a request's origin is allowed to use the underlying service. If it
/// is, pass the request unmodified to the inner service. If it isn't, return an error.
#[derive(Debug, Clone)]
pub struct OriginCheck<S> {
    inner: S,
}

/// Error returned when the origin is not allowed.
#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
pub enum OriginCheckError {
    MissingHeader(String),
    TooManyOfHeader(String, Vec<HeaderValue>),
    InvalidHeader(HeaderValue),
    InvalidUri(String),
    DisallowedOrigin(String),
}

#[derive(Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Hash)]
#[pin_project(project = ResponseFutureProj)]
pub enum ResponseFuture<F: Future> {
    Ok(#[pin] F),
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
            TooManyOfHeader(h, rs) => format!("Too many instances of header {h}: {:?}", rs),
            InvalidHeader(r) => format!("Invalid origin: {:?}", r),
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
        let headers = headers.into_iter().cloned().collect();
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
        Err(_) => return Err(OriginCheckError::InvalidHeader((*header).clone())),
    };
    let uri = match header_str.parse::<Uri>() {
        Err(_) => {
            return Err(OriginCheckError::InvalidUri(header_str.to_string()));
        }
        Ok(r) => r,
    };
    Ok(uri)
}

fn is_valid_origin_header(uri: &Uri) -> bool {
    match (uri.scheme(), uri.authority()) {
        (Some(scheme), Some(authority)) => {
            let minimal_origin = match authority.port_u16() {
                None => format!("{}://{}/", scheme, authority.host()),
                Some(p) => format!("{}://{}:{}/", scheme, authority.host(), p),
            };
            uri.to_string() == minimal_origin
        }
        _ => false,
    }
}

fn potentially_trustworthy(uri: &Uri) -> bool {
    // https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy
    use std::str::FromStr;
    if uri.scheme() == Some(&Scheme::HTTPS) {
        // We don't accept wss:// or file:// schemes, because they seem sketchy in this context
        // (also I think they don't even parse as uris according to `http`)
        return true;
    }
    let mut host = match uri.host() {
        None => return false,
        Some(h) => h,
    };
    if ["localhost", "localhost."].contains(&host)
        || host.ends_with(".localhost")
        || host.ends_with(".localhost.")
    {
        return true;
    }
    if host.starts_with("[") && host.ends_with("]") {
        host = host.strip_prefix("[").unwrap().strip_suffix("]").unwrap();
    }
    if let Ok(i) = std::net::Ipv4Addr::from_str(host) {
        let local_net = cidr::Ipv4Cidr::from_str("127.0.0.0/8").unwrap();
        if local_net.contains(&i) {
            return true;
        }
    }
    if let Ok(i) = std::net::Ipv6Addr::from_str(host) {
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
        Ok(o) => {
            if !is_valid_origin_header(&o) {
                return Err(OriginCheckError::InvalidUri(o.to_string()));
            }
            Some(o)
        }
    };
    let origin_or_referer = match origin {
        Some(o) => o,
        None => match get_exactly_one_uri_header(request, "Referer") {
            Err(e) => return Err(e),
            Ok(r) => r,
        },
    };
    let host_uri = match get_exactly_one_uri_header(request, "Host") {
        Err(e) => return Err(e),
        Ok(h) => h,
    };

    let host_str = match host_uri.host() {
        None => return Err(OriginCheckError::MissingHeader("Host".to_string())),
        Some(host) => host,
    };

    if let Some(uri_host) = request.uri().host() {
        if uri_host != host_str {
            return Err(OriginCheckError::InvalidUri(uri_host.to_string()));
        }
    }

    if origin_or_referer.host() == Some(host_str)
        && origin_or_referer.port() == host_uri.port()
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
pub struct OriginCheckLayer {
    _priv: ()
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
