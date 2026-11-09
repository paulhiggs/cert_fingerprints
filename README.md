# Certificate Fingerprints (`cert_fingerprints.php`)

A single-file PHP script that asks for a URL or hostname, connects to it over TLS, and reports the fingerprints of every certificate the server presents (the leaf certificate plus any intermediates).

It runs from the command line or on a web server.

## Features

- Accepts a bare hostname (`example.com`), a full URL (`https://example.com/path`), or a host with a port (`example.com:8443`)
- Shows SHA-256 and SHA-1 fingerprints in `AA:BB:CC:…` format
- Shows subject, issuer, and validity dates for each certificate
- Works even with expired, self-signed, or hostname-mismatched certificates (verification is deliberately disabled so you can still inspect them)
- Sends SNI, so hosts serving multiple sites return the correct certificate
- Supports IPv4 and IPv6
- Hardened web mode for public hosting (see [Security](#security-web-mode))

## Requirements

- PHP 8.0 or newer
- The PHP **OpenSSL** extension
- Outbound network access on the ports you intend to query

Check your setup with:

```bash
php -m | grep -i openssl
```

## Usage

### Command line

Interactive prompt:

```bash
php cert_fingerprints.php
```

```
Enter a URL or hostname: example.com
```

Or pass the host as an argument:

```bash
php cert_fingerprints.php https://example.com:8443
```

### Web server

1. Upload `cert_fingerprints.php` to any PHP-enabled web server.
2. Open it in a browser.
3. Enter a URL or hostname and click **Look up**.

For a quick local test without a web server:

```bash
php -S localhost:8000 cert_fingerprints.php
```

Then visit <http://localhost:8000>.

## Example output (CLI)

```
Certificates presented by example.com:443 (2)
============================================================

[0] (leaf) example.com
    Issuer:     Example Intermediate CA
    Valid:      2026-01-01 00:00:00 UTC  ->  2026-04-01 23:59:59 UTC
    SHA-256:    AB:CD:EF:...
    SHA-1:      12:34:56:...

[1] (chain) Example Intermediate CA
    Issuer:     Example Root CA
    Valid:      2020-01-01 00:00:00 UTC  ->  2030-01-01 23:59:59 UTC
    SHA-256:    01:23:45:...
    SHA-1:      9A:BC:DE:...
```

(Values above are illustrative.)

## Configuration

Settings are constants at the top of the script.

| Constant | Default | Applies to | Description |
|---|---|---|---|
| `WEB_BLOCK_PRIVATE_ADDRESSES` | `true` | Web | Refuse hosts that resolve to private, loopback, or reserved addresses |
| `WEB_ALLOWED_PORTS` | `[443, 465, 636, 853, 993, 995, 8443]` | Web | Ports visitors may query. Use `[]` to allow any port |
| `WEB_COOLDOWN_SECONDS` | `3` | Web | Minimum seconds between lookups per visitor session |
| `CONNECT_TIMEOUT` | `8` | Both | Connection timeout in seconds |

## Security (web mode)

A tool that makes outbound connections on behalf of visitors can be abused, so web mode includes these protections:

- **SSRF protection:** hostnames are resolved first and rejected if any address is private or reserved. The script then connects to the resolved IP (while still sending the hostname for SNI), which prevents DNS-rebinding tricks.
- **Port allowlist:** only the ports in `WEB_ALLOWED_PORTS` are accepted.
- **CSRF token** on the form and **per-session rate limiting**.
- **Security headers:** `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Cache-Control: no-store`.
- **Input validation and output escaping:** length and port range are checked, and all output is HTML-escaped.

CLI mode applies none of these restrictions, since it runs as you.

**Notes**

- The cooldown is session-based, so clearing cookies bypasses it. For high-traffic public deployments, add rate limiting at the web server or firewall level as well.
- Only disable `WEB_BLOCK_PRIVATE_ADDRESSES` on a trusted network (for example, an internal admin tool).

## How it works

1. The input is parsed into a host and port (default 443).
2. *(Web mode)* The host is resolved and checked against the security rules.
3. A TLS connection is opened with `capture_peer_cert_chain` enabled and verification disabled.
4. Each certificate in the captured chain is parsed with `openssl_x509_parse()` and fingerprinted with `openssl_x509_fingerprint()`.
5. Results are printed as text (CLI) or HTML (web).

## Limitations

- It reports the chain **as sent by the server**, which often omits the root CA. It does not build or validate a full path to a trusted root.
- Because verification is disabled, a successful lookup says nothing about whether the certificate is trusted.
- Only direct TLS connections (`ssl://`) are supported. STARTTLS protocols such as SMTP on port 587 or IMAP on port 143 are not handled; use the implicit-TLS ports (465, 993) instead.

## Troubleshooting

| Problem | Likely cause |
|---|---|
| `The PHP OpenSSL extension is required.` | Enable `extension=openssl` in `php.ini` |
| `Connection failed: ... (error 110/60)` | Timeout. The host is unreachable or a firewall blocks the port |
| `Could not resolve 'host'` | DNS failure or typo in the hostname |
| `Port N is not allowed` | Add the port to `WEB_ALLOWED_PORTS` |
| `...resolves to a private or reserved address` | Intentional SSRF protection; see Configuration |
| Works locally but not on shared hosting | The host may block outbound connections |
