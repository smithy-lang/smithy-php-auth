<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

use Smithy\Auth\AuthSchemeInterface;
use Smithy\Auth\IdentityResolverInterface;
use Smithy\Auth\IdentityResolversInterface;
use Smithy\Auth\SignerInterface;
use Smithy\Core\Shape\OperationInterface;

/**
 * Smithy auth scheme wrapping AWS SigV4 (`aws.auth#sigv4`).
 *
 * Constructed by the per-service client. The scheme knows the service's
 * default signing name and region and hands the pipeline a
 * {@see SigV4Signer} plus the AWS credential resolver registered by
 * the client config.
 */
final class SigV4AuthScheme implements AuthSchemeInterface
{
    public const SCHEME_ID = 'aws.auth#sigv4';

    /**
     * Client context key holding the identity properties that the
     * client config builds.
     */
    public const IDENTITY_CONTEXT_KEY = 'aws.identityContext';

    /**
     * Operation trait requesting an unsigned request payload over HTTPS.
     */
    public const UNSIGNED_PAYLOAD_TRAIT = 'aws.auth#unsignedPayload';

    public function __construct(
        private readonly string $signingName,
        private readonly string $signingRegion,
    ) {}

    public function getSchemeId(): string
    {
        return self::SCHEME_ID;
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function getIdentityProperties(array $context): array
    {
        return $context[self::IDENTITY_CONTEXT_KEY] ?? [];
    }

    public function getIdentityResolver(
        IdentityResolversInterface $resolvers
    ): ?IdentityResolverInterface
    {
        return $resolvers->identityResolver(
            AwsCredentialsIdentityInterface::class
        );
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function getSignerProperties(
        array $context,
        ?OperationInterface $operation = null
    ): array
    {
        $properties = [
            'signingName' => $this->signingName,
            'signingRegion' => $this->signingRegion,
        ];
        if ($operation?->getSchema()->hasTraitById(
            self::UNSIGNED_PAYLOAD_TRAIT
        )) {
            $properties['unsignedPayload'] = true;
        }

        return $properties;
    }

    public function getSigner(): SignerInterface
    {
        return new SigV4Signer(
            $this->signingName,
            $this->signingRegion
        );
    }
}
