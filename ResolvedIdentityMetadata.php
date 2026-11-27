<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth;

/**
 * Describe which provider resolved an identity.
 */
final class ResolvedIdentityMetadata
{
    /** @var non-empty-string Canonical provider name. */
    public readonly string $providerName;

    /**
     * @param string $providerName Canonical provider name.
     * @param list<string> $featureIds Provider feature IDs.
     * @throws \InvalidArgumentException When the provider name is empty.
     */
    public function __construct(
        string $providerName,
        public readonly array $featureIds = []
    )
    {
        if ($providerName === '') {
            throw new \InvalidArgumentException(
                'providerName must not be empty.'
            );
        }
        $this->providerName = $providerName;
    }
}
