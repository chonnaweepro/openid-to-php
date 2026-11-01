<?php

declare(strict_types=1);

// Live transport check for CurlTransport against a real identity provider.
// Needs network. Skipped unless OIDC_LIVE_BASE is set to the realm base URL, for example:
//   OIDC_LIVE_BASE=https://sso.example.com/realms/app php tests/transport_live_test.php
// Only public endpoints and a bogus client are used; no credentials are sent.

require __DIR__ . '/../vendor/autoload.php';

use OpenIdToPhp\CurlTransport;
use OpenIdToPhp\OidcException;

$base = getenv('OIDC_LIVE_BASE');
if (!is_string($base) || trim($base) === '') {
    echo "SKIP: set OIDC_LIVE_BASE to run the live transport checks" . PHP_EOL;
    exit(0);
}
$base = rtrim($base, '/');

$failures = 0;
$total = 0;

function check(string $name, bool $ok): void
{
    global $failures, $total;
    $total++;
    if (!$ok) {
        $failures++;
    }
    echo ($ok ? 'PASS ' : 'FAIL ') . $name . PHP_EOL;
}

/** Runs $fn and returns the OidcException message, or null if it did not throw an OidcException. */
function oidcError(callable $fn): ?string
{
    try {
        $fn();
    } catch (OidcException $e) {
        return $e->getMessage();
    }

    return null;
}

$transport = new CurlTransport();

// 1) TLS verification and a real JSON response: the provider's public key set.
$jwks = $transport->getJson($base . '/protocol/openid-connect/certs');
check('getJson returns the provider key set over verified TLS',
    isset($jwks['keys']) && is_array($jwks['keys']) && $jwks['keys'] !== []);
check('each key has a kid and RSA parameters',
    array_reduce($jwks['keys'], static fn(bool $ok, array $k): bool => $ok && isset($k['kid'], $k['n'], $k['e']), true));

// 2) HTTP error status becomes an OidcException with the status code.
$notFound = oidcError(fn() => $transport->getJson($base . '/protocol/openid-connect/does-not-exist'));
check('HTTP 404 is reported as OidcException', $notFound !== null && str_contains($notFound, 'HTTP 404'));

// 3) Token endpoint error with a bogus client: 4xx with a JSON error body, reported without the body.
$tokenError = oidcError(fn() => $transport->postForm($base . '/protocol/openid-connect/token', [
    'grant_type' => 'authorization_code',
    'client_id' => 'transport-check-no-such-client',
    'client_secret' => 'transport-check-not-a-secret',
    'redirect_uri' => 'https://example.invalid/callback',
    'code' => 'transport-check-code',
    'code_verifier' => 'transport-check-verifier',
]));
check('token endpoint rejects a bogus client with an OidcException',
    $tokenError !== null && preg_match('/HTTP 4\d\d/', $tokenError) === 1);
check('error message does not echo the request or response body',
    $tokenError !== null && !str_contains($tokenError, 'transport-check'));

// 4) Unreachable host is reported as unreachable (connection refused on a closed local port).
$unreachable = oidcError(fn() => $transport->getJson('https://127.0.0.1:9/nothing'));
check('unreachable host is reported as OidcException', $unreachable !== null && str_contains($unreachable, 'unreachable'));

echo PHP_EOL . $total . ' cases, ' . $failures . ' failures' . PHP_EOL;
exit($failures === 0 ? 0 : 1);
