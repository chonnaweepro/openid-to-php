<?php

declare(strict_types=1);

namespace OpenIdToPhp;

use InvalidArgumentException;

/**
 * Small wrapper over the PHP session. Keeps all keys of one client under a single namespace
 * ('oidc' by default), so they cannot clash with other keys in the same session.
 * This is the only class in the library that reads or writes $_SESSION.
 */
final class OidcSession
{
    public function __construct(private readonly string $namespace = 'oidc')
    {
        if (trim($namespace) === '') {
            throw new InvalidArgumentException('session namespace must not be empty');
        }
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$this->namespace][$key] ?? $default;
    }

    public function set(string $key, mixed $value): void
    {
        $_SESSION[$this->namespace][$key] = $value;
    }

    public function forget(string $key): void
    {
        unset($_SESSION[$this->namespace][$key]);
    }

    /** Call after a successful login so the session ID changes (session fixation protection). */
    public function rotateId(): void
    {
        session_regenerate_id(true);
    }

    /** Stores the login state of a request that is waiting for the identity provider. */
    public function savePending(array $pending): void
    {
        $this->set('pending', $pending);
    }

    /** Returns the pending login state and removes it, so it can be used only once. */
    public function takePending(): array
    {
        $pending = $this->get('pending', []);
        $this->forget('pending');

        return is_array($pending) ? $pending : [];
    }

    /**
     * Call after the identity provider accepted the login.
     * Rotates the session ID, stores the user and the ID token (logout hint only), and drops the old CSRF token.
     *
     * @param array<string, mixed> $user the identity your app needs, e.g. ['employee_id' => '1234567']
     */
    public function login(string $idToken, array $user): void
    {
        $this->rotateId();
        $this->set('user', $user);
        $this->set('id_token', $idToken);
        $this->forget('csrf');
    }

    /** @return array<string, mixed>|null */
    public function user(): ?array
    {
        $user = $this->get('user');

        return is_array($user) ? $user : null;
    }

    /** The ID token kept for the logout hint. Never render it. */
    public function idToken(): ?string
    {
        $token = $this->get('id_token');

        return is_string($token) && $token !== '' ? $token : null;
    }

    /** CSRF token for forms in this session. Created on first use and reused until the next login. */
    public function csrfToken(): string
    {
        $token = $this->get('csrf');
        if (!is_string($token) || $token === '') {
            $token = bin2hex(random_bytes(16));
            $this->set('csrf', $token);
        }

        return $token;
    }

    public function verifyCsrf(mixed $submitted): bool
    {
        $expected = $this->get('csrf');

        return is_string($expected) && $expected !== '' && is_string($submitted) && hash_equals($expected, $submitted);
    }

    /** Clears this namespace and ends the PHP session. */
    public function destroy(): void
    {
        unset($_SESSION[$this->namespace]);
        session_destroy();
    }
}
