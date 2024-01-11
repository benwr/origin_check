# origin\_check

An extremely simple Tower middleware layer, that lets you mitigate CSRF attacks
by examining the `Origin` or `Referer` header, and comparing it to the `Host`
and `uri`.

# IMPORTANT NOTES:

This crate makes several assumptions that *must all be true for it to be a good
choice for you:*

1. Your site is accessed exclusively in "secure context"s, like over `https` or
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
   is set to something other than `no-referrer`.

You probably want to set `SameSite=Strict` or `SameSite=Lax` on any
authentication cookies, as additional protection against CSRF.

You likely also want to set `X-Frame-Options: DENY` for your site by default,
to prevent clickjacking, which is a distinct but related problem to CSRF.
