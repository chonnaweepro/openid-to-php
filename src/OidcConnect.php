<?php

declare(strict_types=1);

namespace OpenIdToPhp;

use Throwable;

/**
 * The login and logout steps without HTTP handling. The caller does the redirect, the CSRF check and the response.
 *
 *   startLogin()   -> URL to redirect the browser to
 *   finishLogin()  -> identity of the user (also stored in the session)
 *   logout()       -> URL of the identity provider logout (the local session is already cleared)
 */
final class OidcConnect
{
    /**
     * Builds the whole flow from one config array. Keys are the OidcClient keys, plus:
     *   session_namespace  (optional) session namespace, default 'oidc'
     *
     * Which claims must exist is set with required_claims (OidcClient). Which claims are returned is set per call
     * in finishLogin($query, $claims).
     *
     * $transport and $session are optional; the defaults are CurlTransport and OidcSession.
     *
     * @param array<string, mixed> $config
     */
    public static function create(array $config, ?OidcTransport $transport = null, ?OidcSession $session = null): self
    {
        $client = new OidcClient($config, $transport ?? new CurlTransport());
        $session ??= new OidcSession((string) ($config['session_namespace'] ?? 'oidc'));

        return new self($client, $session);
    }

    public function __construct(
        private readonly OidcClient $client,
        private readonly OidcSession $session,
    ) {}

    public function startLogin(): string
    {
        $begin = $this->client->beginLogin();
        $this->session->savePending($begin['pending']);

        return $begin['url'];
    }

    /**
     * Handles the callback. The pending login is used once, whether this succeeds or not.
     * The identity always contains 'sub' and the claims listed in $claims that are present as non-empty strings.
     *
     * @param array<string, mixed> $query the callback query string, usually $_GET
     * @param list<string> $claims        access-token claims to return, e.g. ['employee_id', 'email']
     * @return array<string, mixed> identity stored in the session, e.g. ['sub' => '...', 'employee_id' => '1234567']
     * @throws OidcException when the callback is not valid or a required claim is missing
     * @throws Throwable when a token or key cannot be verified (see OidcException for the common cases)
     */
    public function finishLogin(array $query, array $claims = []): array
    {
        $result = $this->client->finishLogin($query, $this->session->takePending());

        $identity = ['sub' => (string) $result['claims']['sub']];
        foreach ($claims as $name) {
            $value = $result['claims'][$name] ?? null;
            if (is_string($value) && $value !== '' && $name !== 'sub') {
                $identity[$name] = $value;
            }
        }
        $this->session->login($result['id_token'], $identity);

        return $identity;
    }


    /** @return array<string, mixed>|null the logged-in identity, or null when nobody is logged in */
    public function currentUser(): ?array
    {
        return $this->session->user();
    }

    public function csrfToken(): string
    {
        return $this->session->csrfToken();
    }

    /** Check the CSRF token of a POST form before calling logout(). */
    public function verifyCsrf(mixed $submitted): bool
    {
        return $this->session->verifyCsrf($submitted);
    }

    /** Ends the local session and returns the identity provider logout URL to redirect to. */
    public function logout(): string
    {
        $hint = $this->session->idToken();
        $this->session->destroy();

        return $this->client->endSessionUrl($hint);
    }
}
