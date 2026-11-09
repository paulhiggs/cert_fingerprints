# DVB-I SecurityPolicy Generator (`cert_fingerprints.php`)

A single-file PHP script that asks for a URL or hostname, connects to it over TLS, and reports the fingerprints of every certificate the server presents (the leaf certificate plus any intermediates).

It also generates a complete `SignaturePolicy` XML element, including its `TrustAnchor` and `SubjectConstraint`, that follows the syntax and semantics of **DVB A177r8, clause 7.6.2** (draft ETSI TS 103 770 V1.3.1).

It runs from the command line or on a web server.

## Features

- Accepts a bare hostname (`example.com`), a full URL (`https://example.com/path`), or a host with a port (`example.com:8443`)
- Shows the fingerprints of every certificate in the chain in `AA:BB:CC:…` format, for the algorithms you choose from the SHA-1, SHA-2, SHA-3 and SM3 families (SHA-1, SHA-256, SHA-512 and SM3 by default)
- Shows subject, issuer, and validity dates for each certificate
- Works even with expired, self-signed, or hostname-mismatched certificates (verification is deliberately disabled so you can still inspect them)
- Sends SNI, so hosts serving multiple sites return the correct certificate
- Supports IPv4 and IPv6
- Generates a DVB-I `SignaturePolicy` element (see [SignaturePolicy output](#signaturepolicy-output-dvb-a177r8-clause-762)) with:
  - a `TrustAnchor` containing a `CAFingerprint` for each Certificate Authority in the chain
  - a `SubjectConstraint` containing a `CN` for every hostname associated with the host you entered
- A **Copy to clipboard** button for the `SignaturePolicy` element on the web page
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

Options for the generated `SignaturePolicy`:

```bash
php cert_fingerprints.php example.com --anchor=root     # root-most CA only
php cert_fingerprints.php example.com --anchor=issuer   # issuing CA only
php cert_fingerprints.php example.com --anchor=all      # every CA in the chain (default)

php cert_fingerprints.php example.com --enforcement=warn            # required (default) | warn | vendor
php cert_fingerprints.php example.com --policy-id=urn:acme:policy:1 # the policyId attribute

php cert_fingerprints.php example.com --algorithms=sha-256,sha3-256  # choose fingerprint algorithms
php cert_fingerprints.php example.com --algorithms=all              # every supported algorithm
```

If `--algorithms` is omitted, `sha-1`, `sha-256`, `sha-512` and `sm3` are used. Names are the `@algorithm` values (case-insensitive, comma-separated): `sha-1`, `sha-224`, `sha-256`, `sha-384`, `sha-512`, `sha-512/224`, `sha-512/256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `sm3`, or `all`. An unknown name is an error; a known name your OpenSSL build does not support is skipped with a note.

If `--policy-id` is omitted, the placeholder `urn:example:signature-policy:<host>` is used. Replace it with an identifier you own.

### Web server

1. Upload `cert_fingerprints.php` to any PHP-enabled web server.
2. Open it in a browser.
3. Enter a URL or hostname, tick the fingerprint algorithms you want (SHA-1, SHA-256, SHA-512 and SM3 are ticked by default; any your OpenSSL build lacks are greyed out), and click **Look up**.

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
      sha-256:      AB:CD:EF:...
      sha-512:      45:67:89:...
      sm3:          56:78:9A:...

[1] (chain) Example Intermediate CA
    Issuer:     Example Root CA
    Valid:      2020-01-01 00:00:00 UTC  ->  2030-01-01 23:59:59 UTC
    Fingerprints:
      sha-1:        9A:BC:DE:...
      sha-256:      01:23:45:...
      sha-512:      BC:DE:F0:...
      sm3:          CD:EF:01:...
```

(Values above are illustrative. Every certificate, including the leaf, shows a fingerprint for each selected algorithm (the defaults are shown), and the `SignaturePolicy` element follows after the last certificate.)

## SignaturePolicy output (DVB A177r8 clause 7.6.2)

After the certificate list, the script prints a complete `SignaturePolicy` element as defined in clause 7.6.2.2 (Signature Policy syntax) and 7.6.2.3 (Signature Policy semantics):

```xml
<SignaturePolicy xmlns="urn:dvb:metadata:servicediscovery-types:2026" policyId="urn:example:signature-policy:example.com">
  <Enforcement>required</Enforcement>
  <TrustAnchor>
    <!-- Example Root CA -->
    <CAFingerprint algorithm="sha-1">9A:BC:DE:...</CAFingerprint>
    <CAFingerprint algorithm="sha-256">01:23:45:...</CAFingerprint>
    <CAFingerprint algorithm="sha-512">BC:DE:F0:...</CAFingerprint>
    <CAFingerprint algorithm="sm3">CD:EF:01:...</CAFingerprint>
  </TrustAnchor>
  <SubjectConstraint>
    <CN>example.com</CN> <!-- entered host; certificate subject CN; certificate subjectAltName -->
    <CN>www.example.com</CN> <!-- certificate subjectAltName -->
    <CN>*.example.net</CN> <!-- certificate subjectAltName -->
  </SubjectConstraint>
</SignaturePolicy>
```

(The fingerprints and names above are illustrative.)

### How it maps to the specification

| Specification | What the script does |
|---|---|
| `SignaturePolicy` / `@policyId` (mandatory URI) | `--policy-id`, or the web form field. If left empty, the placeholder `urn:example:signature-policy:<host>` is used. The value must be a URI with a scheme |
| `Enforcement` (mandatory): `required`, `warn` or `vendor` | `--enforcement` or the web selector. Defaults to `required` |
| `TrustAnchor` contains one or more `CAFingerprint` elements (1 .. unbounded) | One `CAFingerprint` is written per selected CA certificate and algorithm |
| `CAFingerprint`: the fingerprint of the Certificate Authority whose certificate must be present in the certificate chain | Only CA certificates are used: certificates with `basicConstraints CA:TRUE` that are not the server's leaf certificate, plus a self-signed leaf. The server's ordinary leaf certificate is never included |
| `CAFingerprint` value pattern: hex byte pairs separated by colons (`HexDigit{2}(:HexDigit{2})*`) | Upper-case, colon-separated hex of the certificate's DER encoding, e.g. `AB:CD:EF:...` |
| `@algorithm` (mandatory): the algorithm used to generate the fingerprint | One `CAFingerprint` per selected algorithm (`--algorithms=` or the web checkboxes; default `sha-1`, `sha-256`, `sha-512`, `sm3`). Available: `sha-1`, `sha-224`, `sha-256`, `sha-384`, `sha-512`, `sha-512/224`, `sha-512/256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512` and `sm3`. The specification does not enumerate `@algorithm` values; `sha-1`, `sha-256` and `sm3` are the names used in clause 7.5.2 and the others follow the same style |
| `SubjectConstraint` (optional, 0 .. 1) with `CN` (1 .. unbounded): the common name, optionally wildcarded, of a host endpoint that may provide the final document or data after any request or DNS redirection | One `CN` per associated hostname (see below). Omitted only if no hostname can be determined, for example an IP address with no names in its certificate |
| Element namespace | `urn:dvb:metadata:servicediscovery-types:2026`, declared once on `SignaturePolicy` and inherited by its children. The elements are declared in the dvbi-types schema (annex A.3), where `elementFormDefault="qualified"`, so they are namespace-qualified |

### Hostnames in SubjectConstraint

Each `CN` is a hostname associated with the host you entered, collected from these sources. A trailing comment on every `CN` says where it came from.

| Source | Notes |
|---|---|
| Entered host | Skipped if you entered an IP address |
| DNS alias (CNAME) chain | Followed up to 10 levels. Controlled by `HOSTNAMES_FROM_CNAME` |
| Server certificate subject CN | From the leaf certificate |
| Server certificate subjectAltName | DNS entries only (IP addresses are not hostnames). Wildcards such as `*.example.com` are kept, because the specification allows wildcarded values |
| Reverse DNS (PTR) names | For the addresses the host resolves to (first 10). Controlled by `HOSTNAMES_FROM_REVERSE_DNS` |

Names are lower-cased, de-duplicated, stripped of any trailing dot, converted to punycode if they are internationalised (this needs the PHP `intl` extension), and checked to be plausible hostnames.

**Review this list before publishing it.** `SubjectConstraint` lists the hosts that are *permitted* to provide a document, so every name you include widens what a client will accept. Reverse-DNS names in particular often belong to a hosting or CDN provider (for example a cloud instance name), so you may want to set `HOSTNAMES_FROM_REVERSE_DNS` to `false`. The script cannot discover hostnames that are reached only through HTTP redirects, because it only makes a TLS connection and does no HTTP request.

### Choosing the CA certificates

| `--anchor=` / web selector | Included |
|---|---|
| `all` (default) | Every CA certificate in the presented chain |
| `root` | Only the top-most CA certificate in the chain |
| `issuer` | Only the CA certificate nearest the server certificate |

**Multiple algorithms:** because each CA appears once per algorithm, a `TrustAnchor` for one CA contains several `CAFingerprint` elements that all describe the same certificate. Any algorithm your PHP/OpenSSL build does not support (for example `sm3` or the `sha3-*` family on older or restricted builds) is silently skipped. MD5 and other legacy digests are deliberately not included. The specification does not say how a client treats several fingerprints, for example whether one matching entry is enough, so check how your DVB-I client interprets them. If it treats each entry as a separate CA, trim `TRUST_ANCHOR_ALGORITHMS` to one entry.

Pinning the root-most CA is usually the most stable choice because intermediates are replaced more often. The specification does not say whether several `CAFingerprint` entries are alternatives or all required, so check how your DVB-I client interprets them before including more than one.

### When no SignaturePolicy is produced

`TrustAnchor` and `CAFingerprint` are mandatory (1 .. unbounded), so if the server sends only its leaf certificate, and that leaf is not self-signed, no valid `SignaturePolicy` can be built. The script says so instead of emitting an empty or invalid element. Many servers omit the root CA, but they normally send the intermediates, which are enough to produce a `TrustAnchor` with `--anchor=issuer`.

## Configuration

Settings are constants at the top of the script.

| Constant | Default | Applies to | Description |
|---|---|---|---|
| `WEB_BLOCK_PRIVATE_ADDRESSES` | `true` | Web | Refuse hosts that resolve to private, loopback, or reserved addresses |
| `WEB_ALLOWED_PORTS` | `[443, 465, 636, 853, 993, 995, 8443]` | Web | Ports visitors may query. Use `[]` to allow any port |
| `WEB_COOLDOWN_SECONDS` | `3` | Web | Minimum seconds between lookups per visitor session |
| `CONNECT_TIMEOUT` | `8` | Both | Connection timeout in seconds |
| `TRUST_ANCHOR_ALGORITHMS` | SHA-1, SHA-2 family, SHA-3 family, SM3 | Both | Map of `@algorithm` value to PHP/OpenSSL digest name. These are the algorithms users can choose from; unsupported entries are skipped. Add or remove entries to change the set |
| `DEFAULT_ALGORITHMS` | `sha-1`, `sha-256`, `sha-512`, `sm3` | Both | Algorithms selected when the user makes no choice |
| `DEFAULT_ENFORCEMENT` | `required` | Both | Default value of `Enforcement` |
| `DEFAULT_POLICY_ID_PREFIX` | `urn:example:signature-policy:` | Both | Prefix of the placeholder `policyId` used when none is given |
| `HOSTNAMES_FROM_CNAME` | `true` | Both | Add the DNS alias (CNAME) chain to `SubjectConstraint` |
| `HOSTNAMES_FROM_REVERSE_DNS` | `true` | Both | Add reverse-DNS (PTR) names to `SubjectConstraint` |
| `DVBI_TYPES_NS` | `urn:dvb:metadata:servicediscovery-types:2026` | Both | Namespace of the generated element |

## Security (web mode)

A tool that makes outbound connections on behalf of visitors can be abused, so web mode includes these protections:

- **SSRF protection:** hostnames are resolved first and rejected if any address is private or reserved. The script then connects to the resolved IP (while still sending the hostname for SNI), which prevents DNS-rebinding tricks.
- **Port allowlist:** only the ports in `WEB_ALLOWED_PORTS` are accepted.
- **CSRF token** on the form and **per-session rate limiting**.
- **Security headers:** `Content-Security-Policy` (scripts are blocked except the page's own copy-to-clipboard handler, which is allowed by a per-request nonce), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Cache-Control: no-store`.
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
6. Associated hostnames are collected (entered host, CNAME chain, certificate names, reverse DNS) and written as the `SubjectConstraint`.
7. Everything is wrapped in a `SignaturePolicy` element with the chosen `Enforcement` and `policyId`.
8. Results are printed as text (CLI) or HTML (web).

## Limitations

- It reports the chain **as sent by the server**, which often omits the root CA. It does not build or validate a full path to a trusted root.
- Because verification is disabled, a successful lookup says nothing about whether the certificate is trusted.
- The `SignaturePolicy` is built from what the server presents and what DNS returns today. It is not a trust decision: verify that the fingerprints belong to the CAs you intend to trust, and that every `CN` is a host you are happy to permit, before publishing it.
- The default `policyId` is a placeholder, and nothing registers or checks it.
- DNS lookups depend on your resolver. If `dns_get_record()` is disabled or blocked, the CNAME and reverse-DNS names are silently missing.
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

## License

Released under the [BSD 3-Clause License](LICENSE). Copyright (c) 2026, paulhiggs.

## Credits

Written by Claude (Anthropic) in collaboration with the requesting user, November 2026. The `SignaturePolicy` output was built from clause 7.6.2 of the DVB A177r8 draft (June 2026) and has not been tested against a DVB-I client or the final published standard.
