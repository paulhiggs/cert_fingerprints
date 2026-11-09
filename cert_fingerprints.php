<?php
declare(strict_types=1);

/**
 * cert_fingerprints.php
 *
 * Prompts for a URL or hostname, connects over TLS, and shows the
 * fingerprints of every certificate the server presents (leaf + intermediates).
 *
 * Works two ways:
 *   CLI:  php cert_fingerprints.php [host]      (prompts if no host given)
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

/** Describe one certificate. */
function describeCert($cert, int $index): array
{
    $info    = openssl_x509_parse($cert) ?: [];
    $subject = $info['subject']['CN'] ?? ($info['subject']['O'] ?? '(none)');
    $issuer  = $info['issuer']['CN']  ?? ($info['issuer']['O']  ?? '(none)');

    return [
        'index'      => $index,
        'subject'    => (string)$subject,
        'issuer'     => (string)$issuer,
        'valid_from' => isset($info['validFrom_time_t']) ? gmdate('Y-m-d H:i:s \U\T\C', $info['validFrom_time_t']) : '?',
        'valid_to'   => isset($info['validTo_time_t'])   ? gmdate('Y-m-d H:i:s \U\T\C', $info['validTo_time_t'])   : '?',
        'sha256'     => colonHex(openssl_x509_fingerprint($cert, 'sha256') ?: ''),
        'sha1'       => colonHex(openssl_x509_fingerprint($cert, 'sha1') ?: ''),
    ];
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
    $input = $argv[1] ?? null;
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
        echo "    SHA-256:    {$c['sha256']}\n";
        echo "    SHA-1:      {$c['sha1']}\n";
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
$error  = null;
$result = null;

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $input = trim((string)($_POST['target'] ?? ''));
    $token = (string)($_POST['csrf'] ?? '');

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
      SHA-256: <code><?= $e($c['sha256']) ?></code><br>
      SHA-1: <code><?= $e($c['sha1']) ?></code>
    </div>
  <?php endforeach; ?>
<?php endif; ?>
</body>
</html>