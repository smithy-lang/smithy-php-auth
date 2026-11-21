<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth;

/**
 * Cache identities returned by another resolver and refresh them before they
 * expire.
 *
 * Cache entries are scoped to the resolution properties. Identities without
 * an expiration remain cached indefinitely unless a matching rejected
 * identity marks the entry for refresh.
 *
 * Refresh follows the credential refresh behavior:
 *
 * - A refresh window opens before expiration. Expired and invalidated
 *   identities refresh as if inside it. A call made while a refresh is
 *   running returns the cached identity.
 * - A failed refresh keeps the cached identity, returns it to the caller and
 *   blocks further refreshes for 300 to 600 seconds. A failure is a thrown
 *   error, a missing identity, or an identity that has already expired.
 * - A {@see NonRecoverableIdentityException} is raised to the caller at once,
 *   sets no backoff, and is re-raised to later callers for 1 to 5 seconds
 *   without contacting the inner resolver.
 * - Without a cached identity, a failed fetch raises the inner error.
 *
 * Unless the caller supplies an advisory window, it comes from the lifetime of
 * the identity most recently returned: 5 minutes for lifetimes up to 20
 * minutes, 15 minutes below 90 minutes, and 60 minutes otherwise.
 *
 * @template TIdentity of IdentityInterface
 * @implements IdentityResolverInterface<TIdentity>
 */
final class CachingIdentityResolver implements IdentityResolverInterface
{
    private const MIN_BACKOFF_SECONDS = 300;
    private const MAX_BACKOFF_SECONDS = 600;
    private const MIN_ERROR_CACHE_SECONDS = 1;
    private const MAX_ERROR_CACHE_SECONDS = 5;

    /** @var IdentityResult<TIdentity>|null */
    private ?IdentityResult $cached = null;

    /** @var array<string, mixed>|null */
    private ?array $cachedProperties = null;

    private bool $refreshRequired = false;

    private bool $refreshing = false;

    private int $advisoryWindowSeconds = 0;

    private ?float $nextRefreshAllowedAt = null;

    private ?NonRecoverableIdentityException $cachedError = null;

    private float $cachedErrorExpiresAt = 0.0;

    /** @var \Closure(TIdentity, IdentityInterface): bool */
    private readonly \Closure $identityMatcher;

    /** @var \Closure(): float */
    private readonly \Closure $clock;

    /** @var \Closure(): float */
    private readonly \Closure $backoffJitter;

    /** @var \Closure(): float */
    private readonly \Closure $errorCacheJitter;

    /**
     * @param IdentityResolverInterface<TIdentity> $inner
     * @param int|null $refreshWindowSeconds Advisory window: start
     *     refreshing this many seconds before expiration. Null derives it
     *     from the identity lifetime.
     * @param null|callable(TIdentity, IdentityInterface): bool
     *     $identityMatcher Compare the cached identity to a rejected identity.
     * @param null|callable(): float $clock Return the current Unix time in
     *     seconds. Null reads `\microtime(true)`.
     * @param null|callable(): float $backoffJitter Return the refresh backoff
     *     in seconds. Null draws from 300 to 600.
     * @param null|callable(): float $errorCacheJitter Return the
     *     non-recoverable error cache period in seconds. Null draws from 1 to
     *     5.
     */
    public function __construct(
        private readonly IdentityResolverInterface $inner,
        private readonly ?int $refreshWindowSeconds = null,
        ?callable $identityMatcher = null,
        ?callable $clock = null,
        ?callable $backoffJitter = null,
        ?callable $errorCacheJitter = null
    )
    {
        if ($refreshWindowSeconds !== null && $refreshWindowSeconds < 0) {
            throw new \InvalidArgumentException(
                'Refresh window must be non-negative.'
            );
        }

        $this->identityMatcher = $identityMatcher === null
            ? static fn(
                IdentityInterface $cached,
                IdentityInterface $rejected
            ): bool => $cached === $rejected
            : \Closure::fromCallable($identityMatcher);
        $this->clock = $clock === null
            ? static fn(): float => \microtime(true)
            : \Closure::fromCallable($clock);
        $this->backoffJitter = $backoffJitter === null
            ? static fn(): float => (float) \random_int(
                self::MIN_BACKOFF_SECONDS,
                self::MAX_BACKOFF_SECONDS
            )
            : \Closure::fromCallable($backoffJitter);
        $this->errorCacheJitter = $errorCacheJitter === null
            ? static fn(): float => (float) \random_int(
                self::MIN_ERROR_CACHE_SECONDS,
                self::MAX_ERROR_CACHE_SECONDS
            )
            : \Closure::fromCallable($errorCacheJitter);
    }

    /** @inheritDoc */
    public function resolveIdentity(array $properties = []): IdentityResult
    {
        if ($this->cached === null || $this->cachedProperties !== $properties) {
            return $this->fetchInitial($properties);
        }

        if (!$this->refreshNeeded($this->cached->identity)) {
            return $this->cached;
        }

        if ($this->rateLimited()) {
            return $this->cached;
        }

        // A reentrant call returns the identity the running refresh is
        // replacing; the running refresh stores the single new result.
        // Mandatory and advisory refreshes share this path because a
        // single-threaded caller cannot wait on the running refresh.
        if ($this->refreshing) {
            return $this->cached;
        }

        return $this->refresh($properties);
    }

    /**
     * Return the wrapped resolver.
     *
     * @return IdentityResolverInterface<TIdentity>
     */
    public function getInner(): IdentityResolverInterface
    {
        return $this->inner;
    }

    /** @inheritDoc */
    public function invalidate(IdentityInterface $rejectedIdentity): void
    {
        if ($this->cached !== null
            && ($this->identityMatcher)(
                $this->cached->identity,
                $rejectedIdentity
            )
        ) {
            $this->refreshRequired = true;
        }

        $this->inner->invalidate($rejectedIdentity);
    }

    /**
     * Fetch with no usable cached identity. Failures raise to the caller.
     *
     * @param array<string, mixed> $properties
     * @return IdentityResult<TIdentity>
     */
    private function fetchInitial(array $properties): IdentityResult
    {
        $this->raiseCachedError();

        $this->refreshing = true;
        try {
            $result = $this->inner->resolveIdentity($properties);
        } catch (NonRecoverableIdentityException $e) {
            $this->cacheError($e);

            throw $e;
        } finally {
            $this->refreshing = false;
        }

        if ($result->identity === null) {
            $this->cached = null;
            $this->cachedProperties = null;

            return $result;
        }

        $this->store($result, $properties);

        return $result;
    }

    /**
     * Refresh a cached identity. Failures return the cached identity.
     *
     * @param array<string, mixed> $properties
     * @return IdentityResult<TIdentity>
     */
    private function refresh(array $properties): IdentityResult
    {
        $this->raiseCachedError();

        $this->refreshing = true;
        try {
            $result = $this->inner->resolveIdentity($properties);
        } catch (NonRecoverableIdentityException $e) {
            $this->cacheError($e);

            throw $e;
        } catch (\Throwable) {
            $result = null;
        } finally {
            $this->refreshing = false;
        }

        $expiration = $result?->identity?->getExpirationTime();
        if ($result === null
            || $result->identity === null
            || ($expiration !== null && $expiration <= ($this->clock)())
        ) {
            $this->nextRefreshAllowedAt = ($this->clock)()
                + ($this->backoffJitter)();

            return $this->cached;
        }

        $this->store($result, $properties);

        return $result;
    }

    /**
     * @param IdentityResult<TIdentity> $result
     * @param array<string, mixed> $properties
     */
    private function store(IdentityResult $result, array $properties): void
    {
        $this->cached = $result;
        $this->cachedProperties = $properties;
        $this->refreshRequired = false;
        $this->nextRefreshAllowedAt = null;
        $this->cachedError = null;

        $expiration = $result->identity?->getExpirationTime();
        $this->advisoryWindowSeconds = $this->refreshWindowSeconds
            ?? ($expiration === null
                ? 0
                : self::advisoryWindowFor($expiration - ($this->clock)()));
    }

    private function cacheError(NonRecoverableIdentityException $error): void
    {
        $this->cachedError = $error;
        $this->cachedErrorExpiresAt = ($this->clock)()
            + ($this->errorCacheJitter)();
    }

    private function raiseCachedError(): void
    {
        if ($this->cachedError !== null
            && ($this->clock)() < $this->cachedErrorExpiresAt
        ) {
            throw $this->cachedError;
        }
    }

    private function rateLimited(): bool
    {
        return $this->nextRefreshAllowedAt !== null
            && ($this->clock)() < $this->nextRefreshAllowedAt;
    }

    private function refreshNeeded(IdentityInterface $identity): bool
    {
        if ($this->refreshRequired) {
            return true;
        }

        $expiry = $identity->getExpirationTime();
        if ($expiry === null) {
            return false;
        }

        return $expiry - ($this->clock)() <= $this->advisoryWindowSeconds;
    }

    private static function advisoryWindowFor(float $lifetimeSeconds): int
    {
        return match (true) {
            $lifetimeSeconds <= 1200 => 300,
            $lifetimeSeconds < 5400 => 900,
            default => 3600,
        };
    }
}
