<?php

declare(strict_types=1);

namespace OpenIdToPhp;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use InvalidArgumentException;

/**
 * OpenID Connect relying-party client: Authorization Code flow with PKCE, nonce, state, and full token checks.
 *
 * Design rules:
 *  - No session, header() or exit(): the caller stores $pending between the two steps and owns redirects.
 *  - HTTP is injected (OidcTransport), so verification runs offline in tests.
 *  - Algorithm allow-list is RS256 only; the header is checked before any key lookup.
 *  - No discovery: endpoints are derived from the issuer (Keycloak default) and can be overridden by prefix.
 */
final class OidcClient
{
    private const ALG = 'RS256';

    private string $issuer;
    private string $backchannel;
    private string $endpointPrefix;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    private string $audience;
    private string $postLogoutRedirectUri;
    /** @var list<string> */
    private array $requiredClaims;
    private int $leeway;
    private string $scope;

    /**
     * Config keys:
     *   issuer                   (required) public issuer URL, must equal the token `iss`
     *   client_id                (required)
     *   client_secret            (required)
     *   redirect_uri             (required) exact callback URL registered at the provider
     *   audience                 (required) value expected in the access token `aud`
     *   backchannel_url          (optional) base URL for token and JWKS calls when it differs from issuer
     *   endpoint_prefix          (optional) default '/protocol/openid-connect' (Keycloak)
     *   post_logout_redirect_uri (optional) needed only for endSessionUrl()
     *   required_claims          (optional) list of access-token claims that must be non-empty strings
     *   scope                    (optional) space-separated scopes, must include 'openid', default 'openid email'
     *   leeway                   (optional) seconds of clock skew allowed, 0-120, default 60
     */
    public function __construct(array $config, private readonly OidcTransport $http)
    {
        foreach (['issuer', 'client_id', 'client_secret', 'redirect_uri', 'audience'] as $key) {
            if (!is_string($config[$key] ?? null) || trim($config[$key]) === '') {
                throw new InvalidArgumentException("Missing OIDC config: {$key}");
            }
        }

        $this->issuer = rtrim($config['issuer'], '/');
        $this->backchannel = rtrim((string) ($config['backchannel_url'] ?? $this->issuer), '/');
        $this->endpointPrefix = rtrim((string) ($config['endpoint_prefix'] ?? '/protocol/openid-connect'), '/');
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUri = $config['redirect_uri'];
        $this->audience = $config['audience'];
        $this->postLogoutRedirectUri = (string) ($config['post_logout_redirect_uri'] ?? '');
        $this->requiredClaims = array_values($config['required_claims'] ?? []);
        $this->leeway = max(0, min(120, (int) ($config['leeway'] ?? 60)));
        $this->scope = trim((string) ($config['scope'] ?? 'openid email'));
        if (!in_array('openid', explode(' ', $this->scope), true)) {
            throw new InvalidArgumentException("scope must include 'openid': {$this->scope}");
        }
    }

    /**
     * Step 1: build the authorization URL. Store $pending server side (e.g. the session) and redirect to $url.
     *
     * @return array{url: string, pending: array{state: string, nonce: string, verifier: string}}
     */
    public function beginLogin(): array
    {
        $pending = [
            'state' => self::b64url(random_bytes(32)),
            'nonce' => self::b64url(random_bytes(32)),
            'verifier' => self::b64url(random_bytes(64)),
        ];

        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => $this->scope,
            'state' => $pending['state'],
            'nonce' => $pending['nonce'],
            'code_challenge' => self::b64url(hash('sha256', $pending['verifier'], true)),
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        return [
            'url' => $this->issuer . $this->endpointPrefix . '/auth?' . $query,
            'pending' => $pending,
        ];
    }

    /**
     * Step 2: handle the redirect callback. $pending is what beginLogin() produced for this browser session.
     * Delete $pending after this call, whether it succeeded or not (single use).
     *
     * @param array<string, mixed> $query   the callback query string ($_GET)
     * @param array<string, mixed> $pending
     * @return array{access_token: string, id_token: string, claims: array<string, mixed>}
     */
    public function finishLogin(array $query, array $pending): array
    {
        if (isset($query['error'])) {
            throw new OidcException('identity provider rejected sign-in');
        }

        $expectedState = (string) ($pending['state'] ?? '');
        $state = $query['state'] ?? null;
        if ($expectedState === '' || !is_string($state) || !hash_equals($expectedState, $state)) {
            throw new OidcException('state mismatch');
        }

        $code = $query['code'] ?? null;
        if (!is_string($code) || $code === '') {
            throw new OidcException('missing authorization code');
        }

        $nonce = (string) ($pending['nonce'] ?? '');
        $verifier = (string) ($pending['verifier'] ?? '');
        if ($nonce === '' || $verifier === '') {
            throw new OidcException('login state incomplete');
        }

        $tokens = $this->http->postForm($this->backchannel . $this->endpointPrefix . '/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code' => $code,
            'code_verifier' => $verifier,
        ]);

        $accessToken = $tokens['access_token'] ?? null;
        $idToken = $tokens['id_token'] ?? null;
        if (!is_string($accessToken) || $accessToken === '' || !is_string($idToken) || $idToken === '') {
            throw new OidcException('token response incomplete');
        }

        $jwks = $this->http->getJson($this->backchannel . $this->endpointPrefix . '/certs');

        $accessClaims = $this->verifyAccessToken($accessToken, $jwks);
        $this->verifyIdToken($idToken, $jwks, $accessClaims, $accessToken, $nonce);

        foreach ($this->requiredClaims as $claim) {
            if (!is_string($accessClaims[$claim] ?? null) || trim($accessClaims[$claim]) === '') {
                throw new OidcException("required claim missing: {$claim}");
            }
        }

        return ['access_token' => $accessToken, 'id_token' => $idToken, 'claims' => $accessClaims];
    }

    /** RP-initiated logout URL. Pass the stored id_token as hint to skip the provider's confirmation page. */
    public function endSessionUrl(?string $idTokenHint = null): string
    {
        $params = [
            'client_id' => $this->clientId,
            'post_logout_redirect_uri' => $this->postLogoutRedirectUri,
        ];
        if ($idTokenHint !== null && $idTokenHint !== '') {
            $params['id_token_hint'] = $idTokenHint;
        }

        return $this->issuer . $this->endpointPrefix . '/logout?'
            . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /** @return array<string, mixed> */
    private function verifyAccessToken(string $jwt, array $jwks): array
    {
        $claims = $this->verifySignature($jwt, $jwks);

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new OidcException('access token issuer mismatch');
        }
        if (!in_array($this->audience, self::audiences($claims), true)) {
            throw new OidcException('access token audience mismatch');
        }
        if (isset($claims['azp']) && $claims['azp'] !== $this->clientId) {
            throw new OidcException('access token azp mismatch');
        }
        if (!is_string($claims['sub'] ?? null) || $claims['sub'] === '') {
            throw new OidcException('access token subject missing');
        }
        $this->requireFresh($claims);

        return $claims;
    }

    /** @param array<string, mixed> $accessClaims */
    private function verifyIdToken(string $jwt, array $jwks, array $accessClaims, string $accessToken, string $nonce): void
    {
        $claims = $this->verifySignature($jwt, $jwks);

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new OidcException('id token issuer mismatch');
        }
        if (!in_array($this->clientId, self::audiences($claims), true)) {
            throw new OidcException('id token audience mismatch');
        }
        if (isset($claims['azp']) && $claims['azp'] !== $this->clientId) {
            throw new OidcException('id token azp mismatch');
        }
        if (!is_string($claims['sub'] ?? null) || !hash_equals((string) $accessClaims['sub'], $claims['sub'])) {
            throw new OidcException('id token subject mismatch');
        }
        if (!is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce'])) {
            throw new OidcException('nonce mismatch');
        }
        if (isset($claims['at_hash'])) {
            $expected = self::b64url(substr(hash('sha256', $accessToken, true), 0, 16));
            if (!is_string($claims['at_hash']) || !hash_equals($expected, $claims['at_hash'])) {
                throw new OidcException('at_hash mismatch');
            }
        }
        $this->requireFresh($claims);
    }

    /**
     * Pins the algorithm before decoding, then verifies the signature with the JWKS key matching the kid.
     * firebase/php-jwt reads JWT::$leeway as a global; it is set for this call only and restored afterwards.
     *
     * @return array<string, mixed>
     */
    private function verifySignature(string $jwt, array $jwks): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new OidcException('token is not a JWS');
        }

        $header = json_decode(self::b64urlDecode($parts[0]), true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($header) || ($header['alg'] ?? null) !== self::ALG || !is_string($header['kid'] ?? null)) {
            throw new OidcException('token header rejected');
        }

        $keys = JWK::parseKeySet($jwks, self::ALG);
        $previous = JWT::$leeway;
        JWT::$leeway = $this->leeway;
        try {
            return (array) JWT::decode($jwt, $keys);
        } finally {
            JWT::$leeway = $previous;
        }
    }

    /** @param array<string, mixed> $claims */
    private function requireFresh(array $claims): void
    {
        $now = time();
        if (!is_int($claims['exp'] ?? null) || $claims['exp'] <= $now - $this->leeway) {
            throw new OidcException('token expired or exp missing');
        }
        if (isset($claims['iat']) && (!is_int($claims['iat']) || $claims['iat'] > $now + $this->leeway)) {
            throw new OidcException('iat invalid');
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @return list<string>
     */
    private static function audiences(array $claims): array
    {
        $aud = $claims['aud'] ?? [];
        $list = is_string($aud) ? [$aud] : (is_array($aud) ? $aud : []);

        return array_values(array_filter($list, 'is_string'));
    }

    private static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private static function b64urlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
        if (!is_string($decoded)) {
            throw new OidcException('invalid base64url');
        }

        return $decoded;
    }
}
