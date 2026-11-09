<?php
declare(strict_types=1);

/**
 * cert_fingerprints.php
 *
 * Prompts for a URL or hostname, connects over TLS, and shows the
 * fingerprints of every certificate the server presents (leaf + intermediates).
 *
 * It also generates a complete <SignaturePolicy> element whose syntax and
 * semantics follow DVB A177r8 (draft ETSI TS 103 770 V1.3.1), clause 7.6.2:
 *   - <Enforcement>       required | warn | vendor
 *   - <TrustAnchor>       one <CAFingerprint> per CA certificate in the chain
 *   - <SubjectConstraint> one <CN> per hostname associated with the host
 *   - @policyId           identifier of the policy
 *
 * Works two ways:
 *   CLI:  php cert_fingerprints.php [host] [--anchor=all|root|issuer]
 *             [--enforcement=required|warn|vendor] [--policy-id=URI]
 *         (prompts if no host given)
 *   Web:  upload to any PHP web server and open it in a browser.
 *
 * Requires PHP 8.0+ with the OpenSSL extension.
 *
 * Written by Claude (Anthropic), November 2026, in collaboration with the
 * requesting user. The SignaturePolicy output was written against the June 2026
 * draft of DVB A177r8 and has not been checked against the final standard.
 */

/* ============================== CONFIG ============================== */

// Web mode only: refuse to connect to private/loopback/reserved addresses.
// Strongly recommended on a public server (prevents SSRF into your network).
const WEB_BLOCK_PRIVATE_ADDRESSES = true;

// Web mode only: ports users may query. Set to [] to allow any port.
const WEB_ALLOWED_PORTS = [443, 465, 636, 853, 993, 995, 8443];

// Web mode only: minimum seconds between lookups per visitor session.
const WEB_COOLDOWN_SECONDS = 3;

// Connection timeout in seconds.
const CONNECT_TIMEOUT = 8;

// DVB A177r8 clause 7.6.2: a CAFingerprint is written for every digest below,
// each with its mandatory @algorithm attribute. The spec does not enumerate
// @algorithm values; sha-1, sha-256 and sm3 are the names used in clause 7.5.2
// and the rest follow the same lower-case, hyphenated style. The right-hand
// side is the name PHP/OpenSSL uses. Any algorithm the local OpenSSL build
// does not support is skipped. Weak or legacy digests (MD5 etc.) are left out.
const TRUST_ANCHOR_ALGORITHMS = [
    'sha-1'       => 'sha1',
    'sha-224'     => 'sha224',
    'sha-256'     => 'sha256',
    'sha-384'     => 'sha384',
    'sha-512'     => 'sha512',
    'sha-512/224' => 'sha512-224',
    'sha-512/256' => 'sha512-256',
    'sha3-224'    => 'sha3-224',
    'sha3-256'    => 'sha3-256',
    'sha3-384'    => 'sha3-384',
    'sha3-512'    => 'sha3-512',
    'sm3'         => 'sm3',
];

// SignaturePolicy defaults (clause 7.6.2). The generated default policyId is a
// placeholder URN: replace it with an identifier you own.
const DEFAULT_ENFORCEMENT = 'required';
const SIGNATURE_POLICY_ENFORCEMENTS = ['required', 'warn', 'vendor'];
const DEFAULT_POLICY_ID_PREFIX = 'urn:example:signature-policy:';

// Sources of hostnames for SubjectConstraint/CN, besides the entered host and
// the names in the server certificate (those two are always used).
const HOSTNAMES_FROM_CNAME = true;          // DNS alias (CNAME) chain of the host
const HOSTNAMES_FROM_REVERSE_DNS = true;    // PTR records of the host's addresses

// XML namespace of the dvbi-types schema (A177r8, annex A.3). TrustAnchor and
// CAFingerprint are declared in it (elementFormDefault="qualified").
const DVBI_TYPES_NS = 'urn:dvb:metadata:servicediscovery-types:2026';

/* ============================ CORE LOGIC ============================ */

/** Turn a URL or bare hostname into [host, port]. */
function parseTarget(string $input): array
{
    $input = trim($input);
    if ($input === '') {
        throw new InvalidArgumentException('No URL or hostname entered.');
    }
    if (strlen($input) > 300) {
        throw new InvalidArgumentException('Input is too long.');
    }
    if (!preg_match('#^[a-z][a-z0-9+.-]*://#i', $input)) {
        $input = 'https://' . $input;
    }
    $parts = parse_url($input);
    if ($parts === false || empty($parts['host'])) {
        throw new InvalidArgumentException("Could not parse a hostname from '$input'.");
    }
    $host = trim($parts['host'], '[]');          // strip IPv6 brackets
    $port = (int)($parts['port'] ?? 443);
    if ($port < 1 || $port > 65535) {
        throw new InvalidArgumentException('Invalid port number.');
    }
    return [$host, $port];
}

/** Resolve a hostname to its public-facing IPs (A + AAAA). */
function resolveHost(string $host): array
{
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return [$host];
    }
    $ips = gethostbynamel($host) ?: [];
    $aaaa = @dns_get_record($host, DNS_AAAA) ?: [];
    foreach ($aaaa as $rec) {
        if (!empty($rec['ipv6'])) {
            $ips[] = $rec['ipv6'];
        }
    }
    if (!$ips) {
        throw new RuntimeException("Could not resolve '$host'.");
    }
    return array_values(array_unique($ips));
}

/** True if the IP is a normal public address. */
function isPublicIp(string $ip): bool
{
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) !== false;
}

/**
 * Connect via TLS and return the certificate chain the server sent.
 * If $connectIp is given we connect to that IP (not the hostname), while
 * still sending $host as the SNI name. This prevents DNS-rebinding tricks.
 */
function fetchCertChain(string $host, int $port, ?string $connectIp = null): array
{
    $context = stream_context_create(['ssl' => [
        'capture_peer_cert_chain' => true,
        // We want fingerprints even for expired / self-signed / mismatched certs.
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
        'SNI_enabled'       => true,
        'peer_name'         => $host,
    ]]);

    $target  = $connectIp ?? $host;
    $address = str_contains($target, ':') ? "[$target]" : $target;   // IPv6 literal

    $stream = @stream_socket_client(
        "ssl://$address:$port",
        $errno,
        $errstr,
        CONNECT_TIMEOUT,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if ($stream === false) {
        throw new RuntimeException("Connection failed: $errstr (error $errno)");
    }

    $params = stream_context_get_params($stream);
    fclose($stream);

    $chain = $params['options']['ssl']['peer_certificate_chain'] ?? [];
    if (!$chain) {
        throw new RuntimeException('Connected, but the server presented no certificates.');
    }
    return $chain;
}

/** Format a hex digest as AA:BB:CC... */
function colonHex(string $hex): string
{
    return implode(':', str_split(strtoupper($hex), 2));
}

/**
 * Fingerprints of one certificate for every algorithm in
 * TRUST_ANCHOR_ALGORITHMS that this PHP/OpenSSL build supports.
 * Returns [@algorithm value => 'AA:BB:...'].
 */
function anchorFingerprints($cert): array
{
    static $supported = null;
    $supported ??= array_map('strtolower', openssl_get_md_methods(true));

    $out = [];
    foreach (TRUST_ANCHOR_ALGORITHMS as $name => $phpName) {
        if (!in_array($phpName, $supported, true)) {
            continue;
        }
        $hex = @openssl_x509_fingerprint($cert, $phpName);
        if (is_string($hex) && $hex !== '') {
            $out[$name] = colonHex($hex);
        }
    }
    return $out;
}

/** Describe one certificate. */
function describeCert($cert, int $index): array
{
    $info    = openssl_x509_parse($cert) ?: [];
    $subject = $info['subject']['CN'] ?? ($info['subject']['O'] ?? '(none)');
    $issuer  = $info['issuer']['CN']  ?? ($info['issuer']['O']  ?? '(none)');

    $constraints = (string)($info['extensions']['basicConstraints'] ?? '');
    $san = (string)($info['extensions']['subjectAltName'] ?? '');
    preg_match_all('/DNS:([^,\s]+)/', $san, $sanMatches);

    return [
        'index'      => $index,
        'is_ca'      => stripos($constraints, 'CA:TRUE') !== false,
        'self_signed' => isset($info['subject'], $info['issuer']) && $info['subject'] === $info['issuer'],
        'subject'    => (string)$subject,
        'cn_list'    => array_map('strval', (array)($info['subject']['CN'] ?? [])),
        'san_dns'    => $sanMatches[1] ?? [],
        'issuer'     => (string)$issuer,
        'valid_from' => isset($info['validFrom_time_t']) ? gmdate('Y-m-d H:i:s \U\T\C', $info['validFrom_time_t']) : '?',
        'valid_to'   => isset($info['validTo_time_t'])   ? gmdate('Y-m-d H:i:s \U\T\C', $info['validTo_time_t'])   : '?',
        'sha256'     => colonHex(openssl_x509_fingerprint($cert, 'sha256') ?: ''),
        'anchor_fps' => anchorFingerprints($cert),
        'sha1'       => colonHex(openssl_x509_fingerprint($cert, 'sha1') ?: ''),
    ];
}

/** Escape text for XML element content / attribute values. */
function xmlEsc(string $s): string
{
    return htmlspecialchars($s, ENT_XML1 | ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/** Make text safe inside an XML comment (no "--", no control characters). */
function xmlCommentSafe(string $s): string
{
    $s = preg_replace('/[\x00-\x1F\x7F]/u', ' ', $s) ?? '';
    $s = str_replace('--', '- -', $s);
    return rtrim($s, '-');
}

/**
 * Pick the certificates that qualify as Certificate Authorities (DVB A177r8,
 * clause 7.6.2.3: "the Certificate Authority whose certificate must be present
 * in the certificate chain"). The server's own (leaf) certificate is only
 * eligible if it is self-signed.
 *
 * $selection: 'all'    every CA certificate in the chain (default)
 *             'root'   only the top-most CA certificate in the chain
 *             'issuer' only the CA certificate nearest the leaf
 */
function selectAnchorCerts(array $certs, string $selection = 'all'): array
{
    $cas = array_values(array_filter(
        $certs,
        static fn(array $c): bool => ($c['index'] > 0 && $c['is_ca']) || $c['self_signed']
    ));
    if (!$cas) {
        return [];
    }
    return match ($selection) {
        'root'   => [end($cas)],
        'issuer' => [$cas[0]],
        default  => $cas,
    };
}

/**
 * Build the TrustAnchor element defined in DVB A177r8 clause 7.6.2.2:
 *
 *   <TrustAnchor>
 *     <CAFingerprint algorithm="...">AA:BB:...</CAFingerprint>   (1..unbounded)
 *   </TrustAnchor>
 *
 * Each selected CA is written once per supported algorithm. The element has
 * no namespace declaration of its own: it inherits it from <SignaturePolicy>.
 * Returns null if the chain contains no CA certificate (CAFingerprint is
 * mandatory, so no valid element can be produced).
 */
function buildTrustAnchorXml(array $certs, string $selection = 'all', string $indent = ''): ?string
{
    $chosen = selectAnchorCerts($certs, $selection);
    if (!$chosen) {
        return null;
    }

    $xml = $indent . '<TrustAnchor>' . "\n";
    foreach ($chosen as $c) {
        $xml .= $indent . '  <!-- ' . xmlCommentSafe($c['subject']) . ' -->' . "\n";
        foreach ($c['anchor_fps'] as $algorithm => $fingerprint) {
            $xml .= $indent . '  <CAFingerprint algorithm="' . xmlEsc($algorithm) . '">'
                  . xmlEsc($fingerprint) . '</CAFingerprint>' . "\n";
        }
    }
    $xml .= $indent . '</TrustAnchor>';
    return $xml;
}

/**
 * Normalise a hostname for SubjectConstraint/CN: lower case, no trailing dot,
 * IDN converted to ASCII, optional leading "*." kept. Returns null for IP
 * addresses and anything that is not a plausible hostname.
 */
function normalizeHostname(string $name): ?string
{
    $name = rtrim(strtolower(trim($name)), '.');
    if ($name === '' || filter_var($name, FILTER_VALIDATE_IP)) {
        return null;
    }
    $wild = str_starts_with($name, '*.');
    $base = $wild ? substr($name, 2) : $name;

    if (preg_match('/[^\x20-\x7e]/', $base)) {
        if (!function_exists('idn_to_ascii')) {
            return null;
        }
        $ascii = idn_to_ascii($base, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
        if ($ascii === false) {
            return null;
        }
        $base = $ascii;
    }
    $label = '[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?';
    if (!preg_match('/^(?=.{1,253}$)' . $label . '(\.' . $label . ')*$/', $base)) {
        return null;
    }
    return $wild ? '*.' . $base : $base;
}

/** Reverse-DNS name (in-addr.arpa / ip6.arpa) for an IP address. */
function ptrName(string $ip): ?string
{
    $bin = @inet_pton($ip);
    if ($bin === false) {
        return null;
    }
    if (strlen($bin) === 4) {
        return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
    }
    return implode('.', array_reverse(str_split(bin2hex($bin)))) . '.ip6.arpa';
}

/**
 * Every hostname associated with the entered host:
 *   - the entered host itself (unless it is an IP address)
 *   - its DNS alias (CNAME) chain
 *   - the subject CN and DNS subjectAltNames of the server certificate
 *   - reverse-DNS (PTR) names of the host's addresses
 * Returns [hostname => [source, ...]], de-duplicated, in discovery order.
 */
function associatedHostnames(string $host, array $leaf): array
{
    $found = [];
    $add = static function (string $name, string $source) use (&$found): void {
        $n = normalizeHostname($name);
        if ($n !== null && !in_array($source, $found[$n] ?? [], true)) {
            $found[$n][] = $source;
        }
    };

    $isIp = filter_var($host, FILTER_VALIDATE_IP) !== false;
    $add($host, 'entered host');

    if (HOSTNAMES_FROM_CNAME && !$isIp) {
        $current = $host;
        for ($i = 0; $i < 10; $i++) {                      // bounded chain
            $records = @dns_get_record($current, DNS_CNAME) ?: [];
            if (empty($records[0]['target'])) {
                break;
            }
            $current = (string)$records[0]['target'];
            $add($current, 'DNS alias (CNAME)');
        }
    }

    foreach ($leaf['cn_list'] ?? [] as $cn) {
        $add($cn, 'certificate subject CN');
    }
    foreach ($leaf['san_dns'] ?? [] as $dns) {
        $add($dns, 'certificate subjectAltName');
    }

    if (HOSTNAMES_FROM_REVERSE_DNS) {
        try {
            $ips = resolveHost($host);
        } catch (Throwable) {
            $ips = [];
        }
        foreach (array_slice($ips, 0, 10) as $ip) {
            $ptr = ptrName($ip);
            if ($ptr === null) {
                continue;
            }
            foreach (@dns_get_record($ptr, DNS_PTR) ?: [] as $record) {
                if (!empty($record['target'])) {
                    $add((string)$record['target'], 'reverse DNS (PTR)');
                }
            }
        }
    }
    return $found;
}

/** Validate the policy id (xs:anyURI, required) or build the default one. */
function resolvePolicyId(string $policyId, string $host): string
{
    $policyId = trim($policyId);
    if ($policyId === '') {
        $policyId = DEFAULT_POLICY_ID_PREFIX . $host;
    }
    if (strlen($policyId) > 300 || !preg_match('/^[A-Za-z][A-Za-z0-9+.\-]*:[^\s<>"\\\\^`{|}]+$/', $policyId)) {
        throw new InvalidArgumentException('The policy ID must be a valid URI, for example urn:example:policy:1.');
    }
    return $policyId;
}

/**
 * Build the complete SignaturePolicy element (DVB A177r8 clause 7.6.2.2):
 *
 *   <SignaturePolicy policyId="...">
 *     <Enforcement>required|warn|vendor</Enforcement>
 *     <TrustAnchor>...</TrustAnchor>
 *     <SubjectConstraint><CN>...</CN> (1..unbounded)</SubjectConstraint>
 *   </SignaturePolicy>
 *
 * $hostnames is the result of associatedHostnames(). Returns null if no
 * TrustAnchor can be built (see buildTrustAnchorXml()).
 */
function buildSignaturePolicyXml(
    array $certs,
    string $selection,
    string $policyId,
    string $enforcement,
    array $hostnames
): ?string {
    if (!in_array($enforcement, SIGNATURE_POLICY_ENFORCEMENTS, true)) {
        throw new InvalidArgumentException('Enforcement must be one of: ' . implode(', ', SIGNATURE_POLICY_ENFORCEMENTS) . '.');
    }
    $trustAnchor = buildTrustAnchorXml($certs, $selection, '  ');
    if ($trustAnchor === null) {
        return null;
    }

    $xml  = '<SignaturePolicy xmlns="' . DVBI_TYPES_NS . '" policyId="' . xmlEsc($policyId) . '">' . "\n";
    $xml .= '  <Enforcement>' . xmlEsc($enforcement) . '</Enforcement>' . "\n";
    $xml .= $trustAnchor . "\n";
    if ($hostnames) {                      // SubjectConstraint is optional (0..1)
        $xml .= '  <SubjectConstraint>' . "\n";
        foreach ($hostnames as $name => $sources) {
            $xml .= '    <CN>' . xmlEsc((string)$name) . '</CN> <!-- '
                  . xmlCommentSafe(implode('; ', $sources)) . ' -->' . "\n";
        }
        $xml .= '  </SubjectConstraint>' . "\n";
    }
    $xml .= '</SignaturePolicy>';
    return $xml;
}

/** Full lookup: returns [host, port, certs[], ip|null]. */
function lookup(string $input, bool $restricted): array
{
    [$host, $port] = parseTarget($input);
    $connectIp = null;

    if ($restricted) {
        if (WEB_ALLOWED_PORTS && !in_array($port, WEB_ALLOWED_PORTS, true)) {
            throw new InvalidArgumentException(
                'Port ' . $port . ' is not allowed. Allowed ports: ' . implode(', ', WEB_ALLOWED_PORTS) . '.'
            );
        }
        $ips = resolveHost($host);
        if (WEB_BLOCK_PRIVATE_ADDRESSES) {
            foreach ($ips as $ip) {
                if (!isPublicIp($ip)) {
                    throw new InvalidArgumentException('That host resolves to a private or reserved address, which is not allowed.');
                }
            }
        }
        $connectIp = $ips[0];
    }

    $chain = fetchCertChain($host, $port, $connectIp);
    $certs = [];
    foreach ($chain as $i => $cert) {
        $certs[] = describeCert($cert, $i);
    }
    return [$host, $port, $certs, $connectIp];
}

if (!extension_loaded('openssl')) {
    $msg = 'The PHP OpenSSL extension is required.';
    if (PHP_SAPI === 'cli') {
        exit($msg . "\n");
    }
    http_response_code(500);
    exit($msg);
}

/* ============================== CLI MODE ============================== */
if (PHP_SAPI === 'cli') {
    $input = null;
    $anchor = 'all';
    $enforcement = DEFAULT_ENFORCEMENT;
    $policyIdArg = '';
    foreach (array_slice($argv, 1) as $arg) {
        if (preg_match('/^--anchor=(all|root|issuer)$/', $arg, $m)) {
            $anchor = $m[1];
        } elseif (preg_match('/^--enforcement=(required|warn|vendor)$/', $arg, $m)) {
            $enforcement = $m[1];
        } elseif (preg_match('/^--policy-id=(.+)$/', $arg, $m)) {
            $policyIdArg = $m[1];
        } elseif ($input === null && !str_starts_with($arg, '--')) {
            $input = $arg;
        }
    }
    if ($input === null) {
        echo 'Enter a URL or hostname: ';
        $input = fgets(STDIN) ?: '';
    }

    try {
        [$policyHost] = parseTarget($input);
        $policyId = resolvePolicyId($policyIdArg, $policyHost);
        [$host, $port, $certs] = lookup($input, false);
    } catch (Throwable $e) {
        fwrite(STDERR, 'Error: ' . $e->getMessage() . "\n");
        exit(1);
    }

    echo "\nCertificates presented by $host:$port (" . count($certs) . ")\n";
    echo str_repeat('=', 60) . "\n";
    foreach ($certs as $c) {
        $role = $c['index'] === 0 ? 'leaf' : 'chain';
        echo "\n[{$c['index']}] ($role) {$c['subject']}\n";
        echo "    Issuer:     {$c['issuer']}\n";
        echo "    Valid:      {$c['valid_from']}  ->  {$c['valid_to']}\n";
        echo "    Fingerprints:\n";
        foreach ($c['anchor_fps'] as $algorithm => $fingerprint) {
            echo '      ' . str_pad($algorithm . ':', 14) . $fingerprint . "\n";
        }
    }

    echo "\nSignaturePolicy (DVB A177r8 clause 7.6.2, --anchor=$anchor, --enforcement=$enforcement)\n";
    echo str_repeat('=', 60) . "\n";
    $policy = buildSignaturePolicyXml($certs, $anchor, $policyId, $enforcement, associatedHostnames($host, $certs[0]));
    if ($policy === null) {
        echo "No CA certificate was presented in the chain, so no TrustAnchor (and therefore no\n";
        echo "valid SignaturePolicy) can be generated. The server may have sent only its leaf certificate.\n";
    } else {
        echo $policy . "\n";
    }
    echo "\n";
    exit(0);
}

/* ============================== WEB MODE ============================== */

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'");
header('Cache-Control: no-store');

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

$e = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$input  = '';
$anchor = 'all';
$enforcement = DEFAULT_ENFORCEMENT;
$policyIdIn  = '';
$error  = null;
$result = null;
$policyXml = null;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $input  = trim((string)($_POST['target'] ?? ''));
    $anchor = in_array($_POST['anchor'] ?? '', ['all', 'root', 'issuer'], true) ? $_POST['anchor'] : 'all';
    $enforcement = in_array($_POST['enforcement'] ?? '', SIGNATURE_POLICY_ENFORCEMENTS, true) ? $_POST['enforcement'] : DEFAULT_ENFORCEMENT;
    $policyIdIn  = trim((string)($_POST['policy_id'] ?? ''));
    $token  = (string)($_POST['csrf'] ?? '');

    if (!hash_equals($_SESSION['csrf'], $token)) {
        http_response_code(403);
        $error = 'Invalid form token. Please reload the page and try again.';
    } elseif (isset($_SESSION['last_lookup']) && time() - $_SESSION['last_lookup'] < WEB_COOLDOWN_SECONDS) {
        http_response_code(429);
        $error = 'Please wait a few seconds between lookups.';
    } else {
        $_SESSION['last_lookup'] = time();
        @set_time_limit(30);
        try {
            [$policyHost] = parseTarget($input);
            $policyId = resolvePolicyId($policyIdIn, $policyHost);
            $result = lookup($input, true);
            $policyXml = buildSignaturePolicyXml(
                $result[2],
                $anchor,
                $policyId,
                $enforcement,
                associatedHostnames($result[0], $result[2][0])
            );
        } catch (Throwable $ex) {
            $error = $ex->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Certificate Fingerprints</title>
<style>
  :root { --bg:#fff; --fg:#1a1a1a; --muted:#666; --border:#ccc; --card:#f8f8f8; --err:#b00020; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#16181d; --fg:#e8e8e8; --muted:#9aa0a6; --border:#3a3f47; --card:#1e2127; --err:#ff6b81; }
  }
  body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg);
         max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
  input[type=text] { width: min(24rem, 100%); padding: .5rem; box-sizing: border-box;
                     background: var(--bg); color: var(--fg); border: 1px solid var(--border); border-radius: 4px; }
  button { padding: .5rem 1rem; cursor: pointer; }
  .cert { border: 1px solid var(--border); background: var(--card); border-radius: 6px;
          padding: .8rem 1rem; margin: 1rem 0; line-height: 1.6; }
  code { word-break: break-all; font-size: .9em; }
  .error { color: var(--err); }
  pre.cert { overflow-x: auto; white-space: pre; }
  table.fp { border-collapse: collapse; margin-top: .4rem; }
  table.fp th { text-align: left; padding: .1rem 1rem .1rem 0; font-weight: 600; white-space: nowrap; vertical-align: top; }
  table.fp td { padding: .1rem 0; }
  select { padding: .45rem; }
  .muted { color: var(--muted); font-size: .9em; }
</style>
</head>
<body>
<h1>Certificate Fingerprints</h1>
<form method="post" autocomplete="off">
  <input type="hidden" name="csrf" value="<?= $e($_SESSION['csrf']) ?>">
  <label>URL or hostname:
    <input type="text" name="target" value="<?= $e($input) ?>" placeholder="example.com" maxlength="300" required autofocus>
  </label>
  <label>TrustAnchor CAs:
    <select name="anchor">
      <option value="all"<?= $anchor === 'all' ? ' selected' : '' ?>>All CAs in chain</option>
      <option value="root"<?= $anchor === 'root' ? ' selected' : '' ?>>Root-most CA only</option>
      <option value="issuer"<?= $anchor === 'issuer' ? ' selected' : '' ?>>Issuing CA only</option>
    </select>
  </label>
  <label>Enforcement:
    <select name="enforcement">
      <?php foreach (SIGNATURE_POLICY_ENFORCEMENTS as $opt): ?>
        <option value="<?= $e($opt) ?>"<?= $enforcement === $opt ? ' selected' : '' ?>><?= $e($opt) ?></option>
      <?php endforeach; ?>
    </select>
  </label>
  <label>Policy ID (URI):
    <input type="text" name="policy_id" value="<?= $e($policyIdIn) ?>" placeholder="<?= $e(DEFAULT_POLICY_ID_PREFIX) ?>&lt;host&gt;" maxlength="300">
  </label>
  <button type="submit">Look up</button>
</form>

<?php if ($error): ?>
  <p class="error">Error: <?= $e($error) ?></p>
<?php elseif ($result): [$host, $port, $certs, $ip] = $result; ?>
  <h2><?= $e($host) ?>:<?= (int)$port ?> &mdash; <?= count($certs) ?> certificate(s)</h2>
  <?php if ($ip && $ip !== $host): ?>
    <p class="muted">Connected to <?= $e($ip) ?></p>
  <?php endif; ?>
  <?php foreach ($certs as $c): ?>
    <div class="cert">
      <strong>[<?= (int)$c['index'] ?>] <?= $c['index'] === 0 ? 'Leaf' : 'Chain' ?>: <?= $e($c['subject']) ?></strong><br>
      Issuer: <?= $e($c['issuer']) ?><br>
      Valid: <?= $e($c['valid_from']) ?> &rarr; <?= $e($c['valid_to']) ?><br>
      <table class="fp">
        <?php foreach ($c['anchor_fps'] as $algorithm => $fingerprint): ?>
          <tr><th scope="row"><?= $e($algorithm) ?></th><td><code><?= $e($fingerprint) ?></code></td></tr>
        <?php endforeach; ?>
      </table>
    </div>
  <?php endforeach; ?>

  <h2>SignaturePolicy</h2>
  <p class="muted">DVB A177r8 clause 7.6.2. The default policy ID is a placeholder: replace it with an identifier you own.</p>
  <?php if ($policyXml === null): ?>
    <p class="error">No CA certificate was presented in the chain, so no TrustAnchor (and therefore no valid SignaturePolicy) can be generated. The server may have sent only its leaf certificate.</p>
  <?php else: ?>
    <pre class="cert"><?= $e($policyXml) ?></pre>
  <?php endif; ?>
<?php endif; ?>
<p class="muted">Written by Claude (Anthropic). SignaturePolicy format follows the DVB A177r8 draft, clause 7.6.2.</p>
</body>
</html>
