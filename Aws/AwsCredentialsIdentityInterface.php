<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

use Smithy\Auth\IdentityInterface;

/**
 * Define the credential accessors AWS signers need.
 *
 * Signers and auth schemes type-hint this interface, so static, session,
 * and refreshable identities all participate in the same signing flow.
 */
interface AwsCredentialsIdentityInterface extends IdentityInterface
{
    /**
     * Return the access key ID.
     */
    public function getAccessKeyId(): string;

    /**
     * Return the secret access key.
     */
    public function getSecretAccessKey(): string;

    /**
     * Return the AWS account ID when known.
     */
    public function getAccountId(): ?string;

    /**
     * Return the session token when present.
     */
    public function getSessionToken(): ?string;
}
