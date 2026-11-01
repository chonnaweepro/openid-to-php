<?php

declare(strict_types=1);

namespace OpenIdToPhp;

/**
 * HTTP access used by OidcClient. Inject a fake in tests; CurlTransport is the production implementation.
 */
interface OidcTransport
{
    /** POST application/x-www-form-urlencoded; the response must be a JSON object. */
    public function postForm(string $url, array $form): array;

    /** GET a JSON object. */
    public function getJson(string $url): array;
}
