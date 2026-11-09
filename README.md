# Certificate Fingerprints (`cert_fingerprints.php`)

A single-file PHP script that asks for a URL or hostname, connects to it over TLS, and reports the fingerprints of every certificate the server presents (the leaf certificate plus any intermediates).

It also generates a `TrustAnchor` XML element that follows the syntax and semantics of **DVB A177r8, clause 7.6.2** (draft ETSI TS 103 770 V1.3.1), ready to paste into a DVB-I Signature Policy.

It runs from the command line or on a web server.

## Features

- Accepts a bare hostname (`example.com`), a full URL (`https://example.com/path`), or a host with a port (`example.com:8443`)
- Shows the fingerprints of every certificate in the chain for all supported algorithms (SHA-1, SHA-2, SHA-3 and SM3 families) in `AA:BB:CC:…` format
- Shows subject, issuer, and validity dates for each certificate
- Works even with expired, self-signed, or hostname-mismatched certificates (verification is deliberately disabled so you can still inspect them)
- Sends SNI, so hosts serving multiple sites return the correct certificate
- Supports IPv4 and IPv6
- Generates a DVB-I `TrustAnchor` element containing a `CAFingerprint` for each Certificate Authority in the chain (see [TrustAnchor output](#trustanchor-output-dvb-a177r8-clause-762))
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

To choose which CA certificates go into the `TrustAnchor` element:

```bash
php cert_fingerprints.php example.com --anchor=root     # root-most CA only
php cert_fingerprints.php example.com --anchor=issuer   # issuing CA only
php cert_fingerprints.php example.com --anchor=all      # every CA in the chain (default)
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
    Fingerprints:
      sha-1:        12:34:56:...
      sha-224:      23:45:67:...
      sha-256:      AB:CD:EF:...
      sha-384:      34:56:78:...
      sha-512:      45:67:89:...
      (... sha-512/224, sha-512/256, sha3-224, sha3-256, sha3-384, sha3-512, sm3)

[1] (chain) Example Intermediate CA
    Issuer:     Example Root CA
    Valid:      2020-01-01 00:00:00 UTC  ->  2030-01-01 23:59:59 UTC
    Fingerprints:
      sha-1:        9A:BC:DE:...
      sha-256:      01:23:45:...
      (... and the same set of algorithms as above)
```

(Values above are illustrative, and the list is abbreviated. Every certificate, including the leaf, shows all fingerprints that your PHP/OpenSSL build supports, and the `TrustAnchor` element follows after the last certificate.)

## TrustAnchor output (DVB A177r8 clause 7.6.2)

After the certificate list, the script prints a `TrustAnchor` element as defined in clause 7.6.2.2 (Signature Policy syntax) and 7.6.2.3 (Signature Policy semantics):

```xml
<TrustAnchor xmlns="urn:dvb:metadata:servicediscovery-types:2026">
  <!-- Example Root CA -->
  <CAFingerprint algorithm="sha-1">9A:BC:DE:...</CAFingerprint>
  <CAFingerprint algorithm="sha-224">11:22:33:...</CAFingerprint>
  <CAFingerprint algorithm="sha-256">01:23:45:...</CAFingerprint>
  <CAFingerprint algorithm="sha-384">AA:BB:CC:...</CAFingerprint>
  <CAFingerprint algorithm="sha-512">DD:EE:FF:...</CAFingerprint>
  <!-- ... sha-512/224, sha-512/256, sha3-224, sha3-256, sha3-384, sha3-512, sm3 -->
</TrustAnchor>
```

(The fingerprints above are illustrative.) Every selected CA is written once per supported digest algorithm.

### How it maps to the specification

| Specification | What the script does |
|---|---|
| `TrustAnchor` contains one or more `CAFingerprint` elements (1 .. unbounded) | One `CAFingerprint` is written per selected CA certificate |
| `CAFingerprint`: the fingerprint of the Certificate Authority whose certificate must be present in the certificate chain | Only CA certificates are used: certificates with `basicConstraints CA:TRUE` that are not the server's leaf certificate, plus a self-signed leaf. The server's ordinary leaf certificate is never included |
| `CAFingerprint` value pattern: hex byte pairs separated by colons (`HexDigit{2}(:HexDigit{2})*`) | Upper-case, colon-separated hex of the certificate's DER encoding, e.g. `AB:CD:EF:...` |
| `@algorithm` (mandatory): the algorithm used to generate the fingerprint | One `CAFingerprint` per algorithm: `sha-1`, `sha-224`, `sha-256`, `sha-384`, `sha-512`, `sha-512/224`, `sha-512/256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512` and `sm3`. The specification does not enumerate `@algorithm` values; `sha-1`, `sha-256` and `sm3` are the names used in clause 7.5.2 and the others follow the same style |
| Element namespace | `urn:dvb:metadata:servicediscovery-types:2026`. `TrustAnchor` and `CAFingerprint` are declared in the dvbi-types schema (annex A.3), where `elementFormDefault="qualified"`, so the element is namespace-qualified |

### Where it goes

`TrustAnchor` is a child of `SignaturePolicy`. The script generates only the `TrustAnchor` element; you add the rest of the policy yourself:

```xml
<SignaturePolicy policyId="urn:example:policy:1">
  <Enforcement>required</Enforcement>   <!-- required | warn | vendor -->
  <TrustAnchor>...</TrustAnchor>         <!-- generated by this script -->
  <SubjectConstraint>                    <!-- optional -->
    <CN>example.com</CN>
  </SubjectConstraint>
</SignaturePolicy>
```

When pasting it inside a document, the `xmlns` declaration on `TrustAnchor` can stay as it is or be replaced by a `dvbi-types` prefix declared higher up.

### Choosing the CA certificates

| `--anchor=` / web selector | Included |
|---|---|
| `all` (default) | Every CA certificate in the presented chain |
| `root` | Only the top-most CA certificate in the chain |
| `issuer` | Only the CA certificate nearest the server certificate |

**Multiple algorithms:** because each CA appears once per algorithm, a `TrustAnchor` for one CA contains several `CAFingerprint` elements that all describe the same certificate. Any algorithm your PHP/OpenSSL build does not support (for example `sm3` or the `sha3-*` family on older or restricted builds) is silently skipped. MD5 and other legacy digests are deliberately not included. The specification does not say how a client treats several fingerprints, for example whether one matching entry is enough, so check how your DVB-I client interprets them. If it treats each entry as a separate CA, trim `TRUST_ANCHOR_ALGORITHMS` to one entry.

Pinning the root-most CA is usually the most stable choice because intermediates are replaced more often. The specification does not say whether several `CAFingerprint` entries are alternatives or all required, so check how your DVB-I client interprets them before including more than one.

### When no TrustAnchor is produced

`CAFingerprint` is mandatory (1 .. unbounded), so if the server sends only its leaf certificate, and that leaf is not self-signed, no valid element can be built. The script says so instead of emitting an empty or invalid element. Many servers omit the root CA, but they normally send the intermediates, which are enough to produce a `TrustAnchor` with `--anchor=issuer`.

## Configuration

Settings are constants at the top of the script.

| Constant | Default | Applies to | Description |
|---|---|---|---|
| `WEB_BLOCK_PRIVATE_ADDRESSES` | `true` | Web | Refuse hosts that resolve to private, loopback, or reserved addresses |
| `WEB_ALLOWED_PORTS` | `[443, 465, 636, 853, 993, 995, 8443]` | Web | Ports visitors may query. Use `[]` to allow any port |
| `WEB_COOLDOWN_SECONDS` | `3` | Web | Minimum seconds between lookups per visitor session |
| `CONNECT_TIMEOUT` | `8` | Both | Connection timeout in seconds |
| `TRUST_ANCHOR_ALGORITHMS` | SHA-1, SHA-2 family, SHA-3 family, SM3 | Both | Map of `@algorithm` value to PHP/OpenSSL digest name. A `CAFingerprint` is written for each supported entry. Add or remove entries to change the set |
| `DVBI_TYPES_NS` | `urn:dvb:metadata:servicediscovery-types:2026` | Both | Namespace of the generated element |

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
5. CA certificates are selected from the chain and written as a `TrustAnchor` element.
6. Results are printed as text (CLI) or HTML (web).

## Limitations

- It reports the chain **as sent by the server**, which often omits the root CA. It does not build or validate a full path to a trusted root.
- Because verification is disabled, a successful lookup says nothing about whether the certificate is trusted.
- The `TrustAnchor` element is built from CA certificates the server actually sends. It is not a trust decision: verify that the fingerprint belongs to the CA you intend to trust before publishing it in a Signature Policy.
- This follows the clause 7.6.2 text of A177r8 as a **draft** (V1.3.1, June 2026). Check it against the final published TS 103 770 before relying on it, since element names and namespaces could still change.
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

## Credits

Written by Claude (Anthropic) in collaboration with the requesting user, November 2026. The `TrustAnchor` output was built from clause 7.6.2 of the DVB A177r8 draft (June 2026) and has not been tested against a DVB-I client or the final published standard.
