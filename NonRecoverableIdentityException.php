<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth;

/**
 * Raised by an identity resolver when a refresh cannot succeed without
 * external action, such as a customer signing in again.
 *
 * {@see CachingIdentityResolver} raises this error to the caller at once,
 * applies no refresh backoff, and re-raises it to later callers for a short
 * jittered period.
 */
class NonRecoverableIdentityException extends \RuntimeException {}
