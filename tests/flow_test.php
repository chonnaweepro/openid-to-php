<?php

declare(strict_types=1);

// Offline checks for OidcConnect: start, finish and logout with a fake identity provider.
// Run: php tests/flow_test.php

// Buffer output so the CLI does not send headers before session_start() runs in later steps.
ob_start();

require __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;
use OpenIdToPhp\OidcClient;
use OpenIdToPhp\OidcConnect;
use OpenIdToPhp\OidcException;
use OpenIdToPhp\OidcSession;
use OpenIdToPhp\OidcTransport;

const FLOW_ISSUER = 'https://sso.example.test/realms/app';
const FLOW_CLIENT = 'app-client';
const FLOW_AUDIENCE = 'app-api';

final class FlowFakeTransport implements OidcTransport
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

$key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
openssl_pkey_export($key, $pem);
$details = openssl_pkey_get_details($key);
$b64 = static fn(string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
$jwks = ['keys' => [[
    'kty' => 'RSA', 'kid' => 'k1', 'alg' => 'RS256', 'use' => 'sig',
    'n' => $b64($details['rsa']['n']), 'e' => $b64($details['rsa']['e']),
]]];

/** Builds a flow whose identity provider answers with the given claims. */
$newFlow = static function (array $claimsOverride = [], array $config = []) use ($pem, $jwks, $b64): array {
    $transport = new FlowFakeTransport();
    $transport->jwks = $jwks;
    $client = new OidcClient($config + [
        'issuer' => FLOW_ISSUER, 'client_id' => FLOW_CLIENT, 'client_secret' => 'test-secret',
        'redirect_uri' => 'https://app.example.test/callback', 'audience' => FLOW_AUDIENCE,
        'post_logout_redirect_uri' => 'https://app.example.test/', 'required_claims' => ['employee_id'],
    ], $transport);

    return [new OidcConnect($client, new OidcSession()), $transport, $pem, $b64, $claimsOverride];
};

/** Starts a login, then prepares tokens for the callback. Returns [state, url]. */
$prepare = static function (array $ctx, array $claimsOverride = [], ?string $nonceOverride = null) use ($newFlow): array {
    [$flow, $transport, $pem, $b64] = $ctx;
    $url = $flow->startLogin();
    parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
    $now = time();
    $access = JWT::encode(array_replace([
        'iss' => FLOW_ISSUER, 'sub' => 'user-1', 'aud' => FLOW_AUDIENCE, 'azp' => FLOW_CLIENT,
        'iat' => $now, 'exp' => $now + 300, 'employee_id' => '1234567',
    ], $claimsOverride), $pem, 'RS256', 'k1');
    $id = JWT::encode([
        'iss' => FLOW_ISSUER, 'sub' => 'user-1', 'aud' => FLOW_CLIENT, 'azp' => FLOW_CLIENT,
        'iat' => $now, 'exp' => $now + 300, 'nonce' => $nonceOverride ?? $q['nonce'],
        'at_hash' => $b64(substr(hash('sha256', $access, true), 0, 16)),
    ], $pem, 'RS256', 'k1');
    $transport->tokens = ['access_token' => $access, 'id_token' => $id];

    return [$q['state'], $url];
};

// 1) startLogin builds an authorization URL with PKCE S256 and the configured scope.
$ctx = $newFlow();
[$state, $url] = $prepare($ctx);
check('startLogin URL uses PKCE S256', str_contains($url, 'code_challenge_method=S256'));
check('startLogin URL includes client and scope', str_contains($url, 'client_id=app-client') && str_contains($url, 'scope=openid%20email'));

// 2) finishLogin returns the identity, stores it, and issues a CSRF token.
[$flow] = $ctx;
$identity = $flow->finishLogin(['code' => 'c', 'state' => $state], ['employee_id']);
check('finishLogin returns sub and the requested claims', $identity === ['sub' => 'user-1', 'employee_id' => '1234567']);
check('currentUser reflects the login', $flow->currentUser() === ['sub' => 'user-1', 'employee_id' => '1234567']);
check('csrfToken is issued and verifies', $flow->csrfToken() !== '' && $flow->verifyCsrf($flow->csrfToken()));

// 3) logout clears the user and returns the provider logout URL with the id token hint.
$logoutUrl = $flow->logout();
check('logout URL carries an id_token_hint', str_contains($logoutUrl, 'id_token_hint='));
check('logout clears the current user', $flow->currentUser() === null);

// 4) a wrong state is rejected, and the pending login is consumed (a retry with the same state also fails).
$ctx = $newFlow();
[$flow] = $ctx;
[$state] = $prepare($ctx);
$rejected = false;
try {
    $flow->finishLogin(['code' => 'c', 'state' => 'forged']);
} catch (OidcException) {
    $rejected = true;
}
check('wrong state is rejected', $rejected && $flow->currentUser() === null);

$retried = false;
try {
    $flow->finishLogin(['code' => 'c', 'state' => $state]);
} catch (OidcException) {
    $retried = true;
}
check('pending login is single use', $retried);

// 5) a token without a required claim is rejected, with a clear message (required_claims enforces it).
$ctx = $newFlow();
[$flow] = $ctx;
[$state] = $prepare($ctx, ['employee_id' => null]);
$message = '';
try {
    $flow->finishLogin(['code' => 'c', 'state' => $state], ['employee_id']);
} catch (OidcException $e) {
    $message = $e->getMessage();
}
check('missing required claim gives a clear error', str_contains($message, 'required claim missing: employee_id'));

// 6) a nonce mismatch is rejected (the ID token must belong to this login).
$ctx = $newFlow();
[$flow] = $ctx;
[$state] = $prepare($ctx, [], 'someone-elses-nonce');
$nonceRejected = false;
try {
    $flow->finishLogin(['code' => 'c', 'state' => $state]);
} catch (OidcException) {
    $nonceRejected = true;
}
check('nonce mismatch is rejected', $nonceRejected);
$flow->logout();

// 8) requested claims are returned with the identity; sub is always there.
$ctx = $newFlow();
[$flow] = $ctx;
[$state] = $prepare($ctx);
$withExtra = $flow->finishLogin(['code' => 'c', 'state' => $state], ['employee_id', 'email']);
check(
    'requested claims are returned, missing optional ones are skipped',
    $withExtra === ['sub' => 'user-1', 'employee_id' => '1234567']
);
$flow->logout();

// 7) create() builds the whole flow from one config array.
$createTransport = new FlowFakeTransport();
$createTransport->jwks = $jwks;
$created = OidcConnect::create([
    'issuer' => FLOW_ISSUER, 'client_id' => FLOW_CLIENT, 'client_secret' => 'test-secret',
    'redirect_uri' => 'https://app.example.test/callback', 'audience' => FLOW_AUDIENCE,
    'scope' => 'openid email', 'session_namespace' => 'flow-create',
], $createTransport);
check('create() builds a flow that starts a login', str_contains($created->startLogin(), 'client_id=' . FLOW_CLIENT));

echo PHP_EOL . $total . ' cases, ' . $failures . ' failures' . PHP_EOL;
exit($failures === 0 ? 0 : 1);
