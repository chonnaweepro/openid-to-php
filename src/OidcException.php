<?php

declare(strict_types=1);

namespace OpenIdToPhp;

use RuntimeException;

/** Any failure in the login flow or token verification. The message is safe to log; it carries no tokens. */
final class OidcException extends RuntimeException {}
