<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

use Smithy\Auth\IdentityInterface;
use Smithy\Auth\IdentityResolverInterface;
use Smithy\Auth\IdentityResult;

/**
 * {@see IdentityResolverInterface} that always returns the same
 * {@see AwsCredentialsIdentityInterface} instance.
 *
 * A client config can accept either a provider or raw credentials; the raw
 * form is wrapped in this class so the downstream pipeline works with the
 * provider contract.
 *
 * `resolveIdentity` returns the exact object handed to the constructor
 * on every call. Stacking a {@see \Smithy\Auth\CachingIdentityResolver}
 * on top adds a single hash-slot read to the resolve path.
 *
 * Also used explicitly when customers hard-code credentials into a
 * client for testing or short-lived scripts:
 *
 * ```php
 * $config = new S3ClientConfig(
 *     credentials: new AwsCredentials('AKIA...', 'secret'),
 * );
 * ```
 *
 * @implements IdentityResolverInterface<AwsCredentialsIdentityInterface>
 */
final class StaticCredentialProvider implements IdentityResolverInterface
{
    public function __construct(
        private readonly AwsCredentialsIdentityInterface $credentials,
    ) {}

    public function resolveIdentity(array $properties = []): IdentityResult
    {
        return IdentityResult::success($this->credentials);
    }

    public function invalidate(IdentityInterface $rejectedIdentity): void {}
}
