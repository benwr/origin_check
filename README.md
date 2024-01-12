# origin\_check

![Crates.io Version](https://img.shields.io/crates/v/origin_check)
![docs.rs](https://img.shields.io/docsrs/origin_check)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/benwr/origin_check/rust.yml)


A minimal `Tower` middleware layer for mitigating CSRF attacks.

Examines the `Origin` or `Referer` header of incoming requests, and compares
it to the target `Host` and `URI`.

```
let (mock_service, _) = tower_test::mock::spawn::<http::Request<()>, ()>();
let csrf_proof_service = origin_check::OriginCheck::new(mock_service);
```

# IMPORTANT NOTES:

This crate makes several assumptions that *must all be true for it to be a good
choice for you:*

1. Your site is accessed exclusively in "secure contexts", like over `https` or
   on `localhost`.
2. State changes are *never performed* in response to `GET` or `HEAD` requests.
   Such requests are _always allowed_ by this service, regardless of CSRF
   indicators.
3. All other requests _should fail_ if the hostname and port of the `Origin` or
   `Referer` does not _exactly_ match the `Host`. This means that you cannot,
   e.g., send POST requests from one subdomain to another, or from one port to
   another.
4. Your users' browsers will set the `Origin` or `Referer` header on
   non-`GET`/-`HEAD` requests, when those requests are initiated by your site.
   In order to ensure this, be careful that the `Referrer-Policy` for your site
   is not set to `no-referrer`.

You probably want to set `SameSite=Strict` or `SameSite=Lax` on any
authentication cookies, as additional protection against CSRF.

You likely also want to set `X-Frame-Options: DENY` for your site by default,
to prevent clickjacking, which is a distinct but related problem to CSRF.
A minimal Tower middleware layer for mitigating CSRF attacks.
