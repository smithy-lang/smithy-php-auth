<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

use Smithy\Auth\IdentityInterface;
use Smithy\Auth\SignerInterface;
use Smithy\Auth\SignerResult;
use Smithy\Core\Transport\TransportRequestInterface;
use Smithy\Http\Message\HttpTransportRequest;

/**
 * Smithy {@see SignerInterface} adapter around {@see SignatureV4}.
 *
 * The pipeline calls `sign($request, $identity, $properties)` once per
 * attempt inside the retry loop, after any `modifyBeforeSigning`
 * interceptor. The adapter:
 *
 *   - Verifies the resolved identity is an {@see AwsCredentialsIdentityInterface}.
 *   - Reads optional signing overrides out of `$properties`
 *     (`signingName`, `signingRegion`, `unsignedPayload`,
 *     `streamingUnsignedTrailer`, `timestamp`)
 *     — these come from a resolved endpoint's auth-scheme entry or from
 *     per-operation static context.
 *   - Delegates to a fresh `SignatureV4` instance sized to the effective
 *     service+region.
 */
final class SigV4Signer implements SignerInterface
{
    public function __construct(
        private readonly string $defaultSigningName,
        private readonly string $defaultSigningRegion
    ) {}

    public function sign(
        TransportRequestInterface $request,
        IdentityInterface $identity,
        array $properties = []
    ): SignerResult
    {
        $transportRequest = HttpTransportRequest::expect($request);
        $httpRequest = $transportRequest->request;
        if (!$identity instanceof AwsCredentialsIdentityInterface) {
            throw new \InvalidArgumentException(
                'SigV4Signer requires AwsCredentialsIdentityInterface; got '
                    . $identity::class
            );
        }

        $signingName = (string) (
            $properties['signingName'] ?? $this->defaultSigningName
        );
        $signingRegion = (string) (
            $properties['signingRegion'] ?? $this->defaultSigningRegion
        );

        $options = [];
        if (($properties['unsignedPayload'] ?? null) === true) {
            $options['unsigned_payload'] = true;
        }
        if (($properties['streamingUnsignedTrailer'] ?? null) === true) {
            $options['streaming_unsigned_trailer'] = true;
        }
        if (isset($properties['timestamp'])
            && \is_int($properties['timestamp'])
        ) {
            $options['timestamp'] = $properties['timestamp'];
        }

        $signer = new SignatureV4($signingName, $signingRegion);
        $result = $signer->signRequest(
            $httpRequest,
            $identity,
            $options
        );
        $signedRequest = HttpTransportRequest::expect(
            $result->signedRequest
        );

        return new SignerResult(
            $transportRequest->withRequest($signedRequest->request),
            $result->signature
        );
    }

    public function close(): void {}
}
