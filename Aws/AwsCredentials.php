<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

/**
 * Store resolved AWS credentials.
 *
 * This is the primary immutable value object returned by credential
 * providers. It represents both long-lived static keys and temporary
 * credentials derived from STS, SSO, IMDS, or container sources.
 */
final class AwsCredentials implements AwsCredentialsIdentityInterface
{
    public function __construct(
        public readonly string $accessKeyId,
        public readonly string $secretAccessKey,
        public readonly ?string $sessionToken = null,
        public readonly ?float $expiration = null,
        public readonly ?string $accountId = null
    ) {}

    /**
     * Return the access key ID.
     */
    public function getAccessKeyId(): string
    {
        return $this->accessKeyId;
    }

    /**
     * Return the secret access key.
     */
    public function getSecretAccessKey(): string
    {
        return $this->secretAccessKey;
    }

    /**
     * Return the AWS account ID when known.
     */
    public function getAccountId(): ?string
    {
        return $this->accountId;
    }

    /**
     * Return the session token when present.
     */
    public function getSessionToken(): ?string
    {
        return $this->sessionToken;
    }

    /**
     * Return the credential expiration time.
     */
    public function getExpirationTime(): ?float
    {
        return $this->expiration;
    }
}
