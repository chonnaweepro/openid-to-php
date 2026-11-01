<?php

declare(strict_types=1);

// Buffer output: in the CLI, printing first would send headers and block session_start() later in this file.
ob_start();

// Offline checks for OidcSession. Run: php tests/session_test.php
// Runs in the CLI session; nothing is sent to a browser.

require __DIR__ . '/../vendor/autoload.php';

use OpenIdToPhp\OidcSession;

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

$session = new OidcSession();
check('missing key returns default', $session->get('missing', 'fallback') === 'fallback');

$session->set('a', 1);
check('set then get', $session->get('a') === 1);
check('value stored under oidc namespace', ($_SESSION['oidc']['a'] ?? null) === 1);

$session->forget('a');
check('forget removes key', $session->get('a') === null);

$first = new OidcSession('ns-one');
$second = new OidcSession('ns-two');
$first->set('k', 'A');
check('namespaces are isolated', $second->get('k') === null && $first->get('k') === 'A');

$_SESSION['unrelated'] = 'kept';
$session->set('b', 2);
$session->destroy();
check('destroy clears the oidc namespace', !isset($_SESSION['oidc']));
check('destroy does not touch other keys', ($_SESSION['unrelated'] ?? null) === 'kept');

try {
    new OidcSession('');
    check('empty namespace is rejected', false);
} catch (InvalidArgumentException) {
    check('empty namespace is rejected', true);
}

$flow = new OidcSession('flow');
$flow->savePending(['state' => 'abc']);
check('takePending returns the saved state', $flow->takePending() === ['state' => 'abc']);
check('takePending is single use', $flow->takePending() === []);

$token = $flow->csrfToken();
check('csrfToken is stable until login', $token !== '' && $token === $flow->csrfToken());
check('verifyCsrf accepts the token', $flow->verifyCsrf($token));
check('verifyCsrf rejects wrong or missing values', !$flow->verifyCsrf('wrong') && !$flow->verifyCsrf(null) && !$flow->verifyCsrf(['x']));

$before = session_id();
$flow->login('id.token.value', ['employee_id' => '1234567']);
check('login stores the user', $flow->user() === ['employee_id' => '1234567']);
check('login stores the id token', $flow->idToken() === 'id.token.value');
check('login rotates the session id', session_id() !== $before);
check('login issues a new csrf token', $flow->csrfToken() !== $token);
check('old csrf token is rejected after login', !$flow->verifyCsrf($token));
$flow->destroy();
check('destroy removes the user', $flow->user() === null);

echo PHP_EOL . $total . ' cases, ' . $failures . ' failures' . PHP_EOL;
exit($failures === 0 ? 0 : 1);
