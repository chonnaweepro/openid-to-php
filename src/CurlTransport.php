<?php

declare(strict_types=1);

namespace OpenIdToPhp;

use CurlHandle;

/**
 * Production transport: cURL with TLS verification always on.
 * On Windows with a cURL build that supports it, native OS CA trust is added to the configured CA bundle.
 */
final class CurlTransport implements OidcTransport
{
    public function __construct(private readonly int $connectTimeout = 5, private readonly int $timeout = 15) {}

    public function postForm(string $url, array $form): array
    {
        return $this->send($url, [
            CURLOPT_POST => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'],
            CURLOPT_POSTFIELDS => http_build_query($form, '', '&', PHP_QUERY_RFC3986),
        ]);
    }

    public function getJson(string $url): array
    {
        return $this->send($url, [CURLOPT_HTTPHEADER => ['Accept: application/json']]);
    }

    private function send(string $url, array $options): array
    {
        $curl = curl_init($url);
        if (!$curl instanceof CurlHandle) {
            throw new OidcException('cURL is unavailable');
        }

        $options += [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];
        if (PHP_OS_FAMILY === 'Windows' && defined('CURLSSLOPT_NATIVE_CA')) {
            $options[CURLOPT_SSL_OPTIONS] = CURLSSLOPT_NATIVE_CA;
        }
        curl_setopt_array($curl, $options);

        $body = curl_exec($curl);
        $status = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $errno = curl_errno($curl);

        // Short messages on purpose: no URL query, no environment details.
        if (!is_string($body)) {
            throw new OidcException("identity provider unreachable (cURL #{$errno})");
        }
        if ($status < 200 || $status >= 300) {
            throw new OidcException("identity provider returned HTTP {$status}");
        }

        $data = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($data)) {
            throw new OidcException('identity provider response is not a JSON object');
        }

        return $data;
    }
}
