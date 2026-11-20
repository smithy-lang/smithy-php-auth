<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

use Psr\Http\Message\RequestInterface;
use Smithy\Core\Checksum\ChecksumAlgorithm;
use Smithy\Http\Message\StreamBodyAdapter;

/**
 * Entry point for sending a request checksum as an `aws-chunked` trailer.
 *
 * {@see applyUnsigned()} prepares a request for the
 * `STREAMING-UNSIGNED-PAYLOAD-TRAILER` mode: it wraps the body in an
 * {@see AwsChunkedRequestStream} and sets the streaming headers. The request
 * checksum interceptor calls it for streaming payloads, and {@see SigV4Signer}
 * then signs with the streaming content hash already on the request (or with
 * the `streamingUnsignedTrailer` signing property).
 *
 * Headers set:
 *
 *  - `Content-Encoding: aws-chunked` (placed before any existing encoding)
 *  - `x-amz-trailer: x-amz-checksum-<algo>`
 *  - `x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER`
 *  - Known payload length: `x-amz-decoded-content-length` with the payload
 *    size and `Content-Length` with the encoded size.
 *  - Unknown payload length: `Transfer-Encoding: chunked`, which the SEP pairs
 *    with omitting `x-amz-decoded-content-length`.
 */
final class AwsChunkedTrailer
{
    public const STREAMING_UNSIGNED_PAYLOAD_TRAILER =
        'STREAMING-UNSIGNED-PAYLOAD-TRAILER';

    /**
     * Encode the request body as `aws-chunked` with an unsigned checksum
     * trailer. The unsigned trailer mode runs over HTTPS.
     *
     * @throws \InvalidArgumentException when the request URI is not HTTPS
     */
    public static function applyUnsigned(
        RequestInterface $request,
        ChecksumAlgorithm $algorithm,
        int $chunkSize = AwsChunkedRequestStream::DEFAULT_CHUNK_SIZE,
    ): RequestInterface
    {
        if (\strtolower($request->getUri()->getScheme()) !== 'https') {
            throw new \InvalidArgumentException(
                'STREAMING-UNSIGNED-PAYLOAD-TRAILER requests use HTTPS.'
            );
        }

        $body = new AwsChunkedRequestStream(
            StreamBodyAdapter::wrap($request->getBody()),
            $algorithm,
            $chunkSize,
        );

        $contentEncoding = $request->getHeaderLine('Content-Encoding');
        $request = $request
            ->withBody($body)
            ->withHeader(
                'Content-Encoding',
                $contentEncoding === ''
                    ? 'aws-chunked'
                    : 'aws-chunked, ' . $contentEncoding
            )
            ->withHeader('x-amz-trailer', $body->trailerName())
            ->withHeader(
                'x-amz-content-sha256',
                self::STREAMING_UNSIGNED_PAYLOAD_TRAILER
            );

        $decodedLength = $body->decodedContentLength();
        if ($decodedLength === null) {
            return $request
                ->withoutHeader('Content-Length')
                ->withoutHeader('x-amz-decoded-content-length')
                ->withHeader('Transfer-Encoding', 'chunked');
        }

        return $request
            ->withoutHeader('Transfer-Encoding')
            ->withHeader('x-amz-decoded-content-length', (string) $decodedLength)
            ->withHeader('Content-Length', (string) $body->length());
    }
}
