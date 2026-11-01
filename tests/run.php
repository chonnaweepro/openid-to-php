<?php

declare(strict_types=1);

// Offline test runner: composer test   (or: php tests/run.php)
// No network, no identity provider. Keys are generated per run; nothing is written to disk.

require __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use OpenIdToPhp\OidcClient;
use OpenIdToPhp\OidcTransport;

final class FakeTransport implements OidcTransport
{
    public array $tokens = [];
    public array $jwks = [];

    public function postForm(string $url, array $form): array
    {
        return $this->tokens;
    }

    public function getJson(string $url): array
    {
        return $this->jwks;
    }
}

const ISSUER = 'https://sso.example.test/realms/app';
const CLIENT = 'app-client';
const AUDIENCE = 'app-api';

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
if ($key === false) {
    fwrite(STDERR, "openssl_pkey_new failed: check OPENSSL_CONF (see README)\n");
    exit(2);
}
openssl_pkey_export($key, $privatePem);
$details = openssl_pkey_get_details($key);
$b64 = static fn(string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
$jwks = ['keys' => [[
    'kty' => 'RSA', 'kid' => 'k1', 'alg' => 'RS256', 'use' => 'sig',
    'n' => $b64($details['rsa']['n']), 'e' => $b64($details['rsa']['e']),
]]];

/**
 * Runs one full login with optional overrides. Returns 'OK' or '<ExceptionClass>: <message>'.
 *
 * @param array<string, mixed> $o overrides: access, id (claim maps), state, pending, id_alg_hs256, tamper
 */
function attempt(array $o = []): string
{
    global $privatePem, $jwks, $b64;

    $transport = new FakeTransport();
    $transport->jwks = $jwks;
    $client = new OidcClient([
        'issuer' => ISSUER, 'client_id' => CLIENT, 'client_secret' => 'test-secret',
        'redirect_uri' => 'https://app.example.test/callback', 'audience' => AUDIENCE,
        'post_logout_redirect_uri' => 'https://app.example.test/', 'required_claims' => ['employee_id'],
    ], $transport);

    $pending = $client->beginLogin()['pending'];

    $now = time();
    $access = JWT::encode(array_replace([
        'iss' => ISSUER, 'sub' => 'user-uuid-1', 'aud' => AUDIENCE, 'azp' => CLIENT,
        'iat' => $now, 'exp' => $now + 300, 'employee_id' => '1234567',
    ], $o['access'] ?? []), $privatePem, 'RS256', 'k1');

    $idPayload = array_replace([
        'iss' => ISSUER, 'sub' => 'user-uuid-1', 'aud' => CLIENT, 'azp' => CLIENT,
        'iat' => $now, 'exp' => $now + 300, 'nonce' => $pending['nonce'],
        'at_hash' => $b64(substr(hash('sha256', $access, true), 0, 16)),
    ], $o['id'] ?? []);

    $idToken = isset($o['id_alg_hs256'])
        ? JWT::encode($idPayload, str_repeat('s', 32), 'HS256', 'k1')
        : JWT::encode($idPayload, $privatePem, 'RS256', 'k1');
    if (isset($o['tamper'])) {
        // Change the payload but keep the old signature: deterministic, unlike flipping the signature's last char.
        [$head, $payloadPart, $sig] = explode('.', $idToken);
        $claims = json_decode(base64_decode(strtr($payloadPart, '-_', '+/')), true);
        $claims['sub'] = 'attacker';
        $idToken = $head . '.' . $b64(json_encode($claims)) . '.' . $sig;
    }
    $transport->tokens = ['access_token' => $access, 'id_token' => $idToken];

    try {
        $client->finishLogin(
            ['code' => 'auth-code-1', 'state' => $o['state'] ?? $pending['state']],
            $o['pending'] ?? $pending,
        );

        return 'OK';
    } catch (Throwable $e) {
        return $e::class . ': ' . $e->getMessage();
    }
}

$cases = [
    ['happy path', [], 'OK'],
    ['state tampered', ['state' => 'forged'], 'state mismatch'],
    ['nonce replaced in id_token', ['id' => ['nonce' => 'other-nonce']], 'nonce mismatch'],
    ['access token audience wrong', ['access' => ['aud' => 'other-app']], 'audience mismatch'],
    ['access token expired', ['access' => ['exp' => time() - 3600]], 'expired'],
    ['id_token sub differs from access sub', ['id' => ['sub' => 'someone-else']], 'subject mismatch'],
    ['at_hash wrong', ['id' => ['at_hash' => 'AAAAAAAAAAAAAAAAAAAAAA']], 'at_hash mismatch'],
    ['id_token azp wrong', ['id' => ['azp' => 'evil-client']], 'azp mismatch'],
    ['required claim empty', ['access' => ['employee_id' => '']], 'required claim missing: employee_id'],
    ['id_token signed HS256 (alg confusion)', ['id_alg_hs256' => true], 'token header rejected'],
    ['id_token payload tampered', ['tamper' => true], 'Signature verification failed'],
];

$failures = 0;
foreach ($cases as [$name, $o, $expected]) {
    $actual = attempt($o);
    if ($expected === 'OK') {
        $pass = $actual === 'OK';
    } elseif ($expected === '') {
        $pass = $actual !== 'OK';
    } else {
        $pass = str_contains(strtolower($actual), strtolower($expected));
    }
    $failures += $pass ? 0 : 1;
    echo ($pass ? 'PASS ' : 'FAIL ') . $name . ' -> ' . $actual . PHP_EOL;
}

// scope configuration (no network: only the authorization URL is built)
$makeClient = static fn(array $extra): OidcClient => new OidcClient(array_merge([
    'issuer' => ISSUER, 'client_id' => CLIENT, 'client_secret' => 'test-secret',
    'redirect_uri' => 'https://app.example.test/callback', 'audience' => AUDIENCE,
], $extra), new FakeTransport());

$rejectsScope = static function (array $extra) use ($makeClient): bool {
    try {
        $makeClient($extra);

        return false;
    } catch (InvalidArgumentException) {
        return true;
    }
};

$scopeChecks = [
    ['default scope is openid email', str_contains($makeClient([])->beginLogin()['url'], 'scope=openid%20email')],
    ['custom scope is sent', str_contains($makeClient(['scope' => 'openid profile'])->beginLogin()['url'], 'scope=openid%20profile')],
    ['scope without openid is rejected', $rejectsScope(['scope' => 'email'])],
];
foreach ($scopeChecks as [$name, $ok]) {
    $failures += $ok ? 0 : 1;
    echo ($ok ? 'PASS ' : 'FAIL ') . $name . PHP_EOL;
}

echo PHP_EOL . (count($cases) + count($scopeChecks)) . ' cases, ' . $failures . ' failures' . PHP_EOL;
exit($failures === 0 ? 0 : 1);
