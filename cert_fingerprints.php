<?php
declare(strict_types=1);

/**
 * cert_fingerprints.php
 *
 * Prompts for a URL or hostname, connects over TLS, and shows the
 * fingerprints of every certificate the server presents (leaf + intermediates).
 *
 * It also generates a <TrustAnchor> element whose syntax and semantics follow
 * DVB A177r8 (draft ETSI TS 103 770 V1.3.1), clause 7.6.2: one <CAFingerprint>
 * per Certificate Authority certificate found in the presented chain.
 *
 * Works two ways:
 *   CLI:  php cert_fingerprints.php [host] [--anchor=all|root|issuer]
 *         (prompts if no host given)
 *   Web:  upload to any PHP web server and open it in a browser.
 *
 * Requires PHP 8.0+ with the OpenSSL extension.
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

    return [
        'index'      => $index,
        'is_ca'      => stripos($constraints, 'CA:TRUE') !== false,
        'self_signed' => isset($info['subject'], $info['issuer']) && $info['subject'] === $info['issuer'],
        'subject'    => (string)$subject,
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
 * Each selected CA is written once per supported algorithm.
 *
 * Returns the XML string, or null if the chain contains no CA certificate
 * (CAFingerprint is mandatory, so no valid element can be produced).
 */
function buildTrustAnchorXml(array $certs, string $selection = 'all'): ?string
{
    $chosen = selectAnchorCerts($certs, $selection);
    if (!$chosen) {
        return null;
    }

    $xml  = '<TrustAnchor xmlns="' . DVBI_TYPES_NS . '">' . "\n";
    foreach ($chosen as $c) {
        $xml .= '  <!-- ' . xmlCommentSafe($c['subject']) . ' -->' . "\n";
        foreach ($c['anchor_fps'] as $algorithm => $fingerprint) {
            $xml .= '  <CAFingerprint algorithm="' . xmlEsc($algorithm) . '">'
                  . xmlEsc($fingerprint) . '</CAFingerprint>' . "\n";
        }
    }
    $xml .= '</TrustAnchor>';
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
    foreach (array_slice($argv, 1) as $arg) {
        if (preg_match('/^--anchor=(all|root|issuer)$/', $arg, $m)) {
            $anchor = $m[1];
        } elseif ($input === null && !str_starts_with($arg, '--')) {
            $input = $arg;
        }
    }
    if ($input === null) {
        echo 'Enter a URL or hostname: ';
        $input = fgets(STDIN) ?: '';
    }

    try {
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

    echo "\nTrustAnchor (DVB A177r8 clause 7.6.2, --anchor=$anchor)\n";
    echo str_repeat('=', 60) . "\n";
    $ta = buildTrustAnchorXml($certs, $anchor);
    if ($ta === null) {
        echo "No CA certificate was presented in the chain, so no TrustAnchor can be generated.\n";
        echo "(The server may have sent only its leaf certificate.)\n";
    } else {
        echo $ta . "\n";
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
$error  = null;
$result = null;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $input  = trim((string)($_POST['target'] ?? ''));
    $anchor = in_array($_POST['anchor'] ?? '', ['all', 'root', 'issuer'], true) ? $_POST['anchor'] : 'all';
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
            $result = lookup($input, true);
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

  <h2>TrustAnchor</h2>
  <p class="muted">DVB A177r8 clause 7.6.2 &mdash; goes inside a <code>SignaturePolicy</code> element.</p>
  <?php $ta = buildTrustAnchorXml($certs, $anchor); ?>
  <?php if ($ta === null): ?>
    <p class="error">No CA certificate was presented in the chain, so no TrustAnchor can be generated. The server may have sent only its leaf certificate.</p>
  <?php else: ?>
    <pre class="cert"><?= $e($ta) ?></pre>
  <?php endif; ?>
<?php endif; ?>
</body>
</html>
