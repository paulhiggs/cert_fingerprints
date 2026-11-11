<?php
declare(strict_types=1);

/**
 * cert_lookup.php
 *
 * Library for fetching the certificate chain a TLS server presents and
 * fingerprinting each certificate. It only defines constants and functions,
 * produces no output, and has no side effects, so other scripts can use it:
 *
 *   require_once __DIR__ . '/cert_lookup.php';
 *
 *   $result = lookup('example.com', selectAlgorithms(['sha-256']));
 *   foreach ($result['certs'] as $cert) {
 *       echo $cert['subject'], ' ', $cert['anchor_fps']['sha-256'], "\n";
 *   }
 *
 * dvbi_securitypolicy.php uses it to build a DVB-I SignaturePolicy.
 *
 * Requires PHP 8.0+ with the OpenSSL extension.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026, Paul Higgs. See the LICENSE file.
 */

/* ============================== CONFIG ============================== */
// Each constant is only defined if the including script has not already
// defined it, so a caller can override any of them before require_once.

// Connection timeout in seconds (default for lookup()'s 'timeout' option).
defined('CONNECT_TIMEOUT') || define('CONNECT_TIMEOUT', 8);

// Fingerprint algorithms callers can choose from. Keys are the @algorithm
// names used in DVB-I (A177r8 does not enumerate them; sha-1, sha-256 and sm3
// are the names used in clause 7.5.2 and the rest follow the same lower-case,
// hyphenated style). Values are the names PHP/OpenSSL uses. Any algorithm the
// local OpenSSL build does not support is skipped. Weak or legacy digests
// (MD5 etc.) are left out.
defined('TRUST_ANCHOR_ALGORITHMS') || define('TRUST_ANCHOR_ALGORITHMS', [
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
]);

// Algorithms used when the caller makes no choice. Keys of TRUST_ANCHOR_ALGORITHMS.
defined('DEFAULT_ALGORITHMS') || define('DEFAULT_ALGORITHMS', ['sha-1', 'sha-256', 'sha-512', 'sm3']);

/* ============================ FUNCTIONS ============================ */

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
function fetchCertChain(
    string $host,
    int $port,
    ?string $connectIp = null,
    int $timeout = CONNECT_TIMEOUT
): array {
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
        $timeout,
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

/** True if this PHP/OpenSSL build supports the given @algorithm name. */
function isAlgorithmSupported(string $name): bool
{
    static $supported = null;
    $supported ??= array_map('strtolower', openssl_get_md_methods(true));
    return isset(TRUST_ANCHOR_ALGORITHMS[$name])
        && in_array(TRUST_ANCHOR_ALGORITHMS[$name], $supported, true);
}

/**
 * Validate a user's algorithm selection. Accepts @algorithm names (any case);
 * "all" selects every supported algorithm. Returns the names in the order of
 * TRUST_ANCHOR_ALGORITHMS. Throws if a name is unknown or nothing usable is left.
 */
function selectAlgorithms(array $requested): array
{
    $requested = array_values(array_filter(array_map(
        static fn($a): string => strtolower(trim((string)$a)),
        $requested
    ), 'strlen'));
    if (in_array('all', $requested, true)) {
        $requested = array_keys(TRUST_ANCHOR_ALGORITHMS);
    }
    $unknown = array_diff($requested, array_keys(TRUST_ANCHOR_ALGORITHMS));
    if ($unknown) {
        throw new InvalidArgumentException(
            'Unknown algorithm(s): ' . implode(', ', $unknown) . '. Choose from: '
            . implode(', ', array_keys(TRUST_ANCHOR_ALGORITHMS)) . ', or all.'
        );
    }
    $chosen = array_values(array_filter(
        array_keys(TRUST_ANCHOR_ALGORITHMS),
        static fn(string $n): bool => in_array($n, $requested, true) && isAlgorithmSupported($n)
    ));
    if (!$chosen) {
        throw new InvalidArgumentException('Select at least one fingerprint algorithm that this server supports.');
    }
    return $chosen;
}

/**
 * Fingerprints of one certificate for each of the given @algorithm names
 * (keys of TRUST_ANCHOR_ALGORITHMS) that this PHP/OpenSSL build supports.
 * Returns [@algorithm value => 'AA:BB:...'].
 */
function anchorFingerprints($cert, array $algorithms): array
{
    $out = [];
    foreach ($algorithms as $name) {
        if (!isAlgorithmSupported($name)) {
            continue;
        }
        $phpName = TRUST_ANCHOR_ALGORITHMS[$name];
        $hex = @openssl_x509_fingerprint($cert, $phpName);
        if (is_string($hex) && $hex !== '') {
            $out[$name] = colonHex($hex);
        }
    }
    return $out;
}

/** Describe one certificate. */
function describeCert($cert, int $index, array $algorithms): array
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
        'anchor_fps' => anchorFingerprints($cert, $algorithms),
    ];
}

/**
 * Connect to a host and describe every certificate it presents.
 *
 *   $input       URL, hostname, or host:port (see parseTarget()). Port 443
 *                is used when none is given.
 *   $algorithms  @algorithm names to fingerprint with (keys of
 *                TRUST_ANCHOR_ALGORITHMS). Use selectAlgorithms() to validate
 *                user input. Names this OpenSSL build lacks are skipped.
 *   $options     'allowed_ports' => int[]  reject any other port ([] = any; default)
 *                'block_private' => bool   refuse hosts that resolve to a private,
 *                                          loopback or reserved address (default false)
 *                'timeout'       => int    connection timeout in seconds
 *                                          (default CONNECT_TIMEOUT)
 *
 * When either restriction is set, the host is resolved first and the
 * connection is made to the checked address (still sending the hostname as
 * SNI), so DNS cannot be switched to another address between check and use.
 * Set both when the input comes from someone you do not trust.
 *
 * Certificate verification is deliberately disabled, so expired, self-signed
 * and mismatched certificates are still returned. A successful lookup says
 * nothing about whether the certificate is trusted.
 *
 * Returns:
 *   [
 *     'host'  => string,      host name (or IP) as parsed from $input
 *     'port'  => int,
 *     'ip'    => ?string,     address connected to, or null if not resolved first
 *     'certs' => array[],     one describeCert() array per certificate, leaf first
 *   ]
 *
 * Throws InvalidArgumentException for bad input or a refused target, and
 * RuntimeException for missing OpenSSL, DNS or connection failures.
 */
function lookup(string $input, array $algorithms = DEFAULT_ALGORITHMS, array $options = []): array
{
    if (!extension_loaded('openssl')) {
        throw new RuntimeException('The PHP OpenSSL extension is required.');
    }
    $allowedPorts = array_map('intval', (array)($options['allowed_ports'] ?? []));
    $blockPrivate = (bool)($options['block_private'] ?? false);
    $timeout      = (int)($options['timeout'] ?? CONNECT_TIMEOUT);

    [$host, $port] = parseTarget($input);
    $connectIp = null;

    if ($allowedPorts && !in_array($port, $allowedPorts, true)) {
        throw new InvalidArgumentException(
            'Port ' . $port . ' is not allowed. Allowed ports: ' . implode(', ', $allowedPorts) . '.'
        );
    }
    if ($allowedPorts || $blockPrivate) {
        $ips = resolveHost($host);
        if ($blockPrivate) {
            foreach ($ips as $ip) {
                if (!isPublicIp($ip)) {
                    throw new InvalidArgumentException('That host resolves to a private or reserved address, which is not allowed.');
                }
            }
        }
        $connectIp = $ips[0];
    }

    $chain = fetchCertChain($host, $port, $connectIp, $timeout);
    $certs = [];
    foreach ($chain as $i => $cert) {
        $certs[] = describeCert($cert, $i, $algorithms);
    }
    return ['host' => $host, 'port' => $port, 'ip' => $connectIp, 'certs' => $certs];
}
