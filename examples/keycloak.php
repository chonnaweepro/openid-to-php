<?php

declare(strict_types=1);

// Keycloak example in one file. Run locally:
//   php -S 127.0.0.1:8080 -t examples
// Pages: keycloak.php (home), ?action=login, ?action=callback, POST ?action=logout
//
// All state of this client lives under $_SESSION['oidc'] so it cannot clash with other keys in the session.

require __DIR__ . '/../vendor/autoload.php';

use OpenIdToPhp\OidcConnect;

/**
 * Page actions for the Keycloak example. Each action ends the request with exit (redirect or error response).
 */
final class KeycloakPages
{
    public function __construct(
        private readonly OidcConnect $flow,
        private readonly string $homeUrl = 'keycloak.php', // where to go after a successful login
    ) {}

    /** Routes ?action= to a method. An empty or unknown action shows the home page. */
    public function handle(string $action): void
    {
        switch ($action) {
            case 'login':
                $this->login();
                break;
            case 'callback':
                $this->callback();
                break;
            case 'logout':
                $this->logout();
                break;
            default:
                $this->home();
                break;
        }
    }

    public function login(): never
    {
        header('Location: ' . $this->flow->startLogin());
        exit;
    }

    public function callback(): never
    {
        try {
            $this->flow->finishLogin($_GET, ['employee_id']);
        } catch (Throwable $e) {
            error_log('login failed: ' . $e->getMessage());
            http_response_code(401);
            exit('Login failed.');
        }
        header('Location: ' . $this->homeUrl);
        exit;
    }

    public function logout(): never
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$this->flow->verifyCsrf($_POST['csrf'] ?? null)) {
            http_response_code(403);
            exit('Forbidden');
        }
        header('Location: ' . $this->flow->logout());
        exit;
    }

    public function home(): void
    {
        $user = $this->flow->currentUser();
        if ($user === null) {
            echo '<a href="?action=login">Login with Keycloak</a>';
            return;
        }
        ?>
        <p>Hello, employee <?= htmlspecialchars($user['employee_id'], ENT_QUOTES) ?></p>
        <form method="post" action="?action=logout">
          <input type="hidden" name="csrf" value="<?= htmlspecialchars($this->flow->csrfToken(), ENT_QUOTES) ?>">
          <button type="submit">Logout</button>
        </form>
        <?php
    }
}

$flow = OidcConnect::create([
    'issuer' => getenv('OIDC_ISSUER'),
    'client_id' => getenv('OIDC_CLIENT_ID'),
    'client_secret' => getenv('OIDC_CLIENT_SECRET'),
    'redirect_uri' => getenv('OIDC_REDIRECT_URI'),
    'audience' => getenv('OIDC_AUDIENCE'),
    'post_logout_redirect_uri' => getenv('OIDC_POST_LOGOUT_URI'),
    'required_claims' => ['employee_id'],
    'scope' => 'openid email',
]);

(new KeycloakPages($flow, 'keycloak.php'))->handle($_GET['action'] ?? '');
