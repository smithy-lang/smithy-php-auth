<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\UriInterface;
use Smithy\Auth\SignerResult;
use Smithy\Http\Message\HttpTransportRequest;
use Smithy\Http\Message\Request;
use Smithy\Http\Message\RequestStreamInterface;
use Smithy\Http\Message\StreamBodyAdapter;

/**
 * AWS Signature Version 4 request signer.
 *
 * Signs and pre-signs PSR-7 requests per the AWS SigV4 specification
 * (Task 1: canonical request; Task 2: string to sign; Task 3: signing
 * key derivation; Task 4: Authorization header).
 *
 * This is a straight port of the working implementation at
 * `../aws-sdk-php-v4/aws-sdk-php/src/Core/Signature/SignatureV4.php`,
 * adapted only for the V4 codebase namespaces and credential type.
 *
 * The class is stateless per-request — a single `SignatureV4($service,
 * $region)` instance can be reused across signings, or reconstructed
 * on demand by {@see SigV4Signer}.
 */
final class SignatureV4
{
    private const ALGORITHM = 'AWS4-HMAC-SHA256';
    private const TERMINATOR = 'aws4_request';

    /**
     * Headers excluded from signing. Lowercase. Every other header is
     * included in the signed headers set.
     *
     * @var list<string>
     */
    private array $unsignableHeaders = [
        'cache-control',
        'content-type',
        'content-length',
        'expect',
        'max-forwards',
        'pragma',
        'range',
        'te',
        'if-match',
        'if-none-match',
        'if-modified-since',
        'if-unmodified-since',
        'if-range',
        'accept',
        'authorization',
        'proxy-authorization',
        'from',
        'referer',
        'user-agent',
        'x-amzn-trace-id',
    ];

    public function __construct(
        private readonly string $service,
        private readonly string $region,
    ) {}

    /**
     * Sign a PSR-7 request with AWS Signature V4.
     *
     * Returns the signed request and the hexadecimal signature used by
     * its `Authorization` header.
     *
     * The request bears the `Authorization`, `X-Amz-Date`,
     * `X-Amz-Content-Sha256`, and (if applicable) `X-Amz-Security-Token`
     * headers.
     *
     * `streaming_unsigned_trailer` signs with the
     * `STREAMING-UNSIGNED-PAYLOAD-TRAILER` content hash for `aws-chunked`
     * bodies prepared by {@see AwsChunkedTrailer::applyUnsigned()}.
     *
     * `disable_double_encoding` signs the request path exactly as it is
     * sent: the path is percent-encoded once and its empty, `.` and `..`
     * segments are kept. S3 requires this form.
     *
     * @param array{
     *     timestamp?: int,
     *     unsigned_payload?: bool,
     *     streaming_unsigned_trailer?: bool,
     *     disable_double_encoding?: bool,
     * } $options
     */
    public function signRequest(
        RequestInterface $request,
        AwsCredentialsIdentityInterface $credentials,
        array $options = [],
    ): SignerResult
    {
        $timestamp = $options['timestamp'] ?? time();
        $dateTime = gmdate('Ymd\THis\Z', $timestamp);
        $date = gmdate('Ymd', $timestamp);

        // Calculate the content hash before applying the headers that
        // participate in canonicalization.
        $contentHash = $this->getContentHash($request, $options);
        $headers = [
            'x-amz-date' => ['X-Amz-Date', [$dateTime]],
        ];

        $sessionToken = $credentials->getSessionToken();
        if ($sessionToken !== null) {
            $headers['x-amz-security-token'] = [
                'X-Amz-Security-Token',
                [$sessionToken],
            ];
        }

        if ($request->getHeaderLine('X-Amz-Content-Sha256')
                !== $contentHash
        ) {
            $headers['x-amz-content-sha256'] = [
                'X-Amz-Content-Sha256',
                [$contentHash],
            ];
        }

        $request = $request->withoutHeader('Authorization');
        if ($request instanceof Request) {
            $request = $request->withNormalizedHeaders($headers);
        } else {
            foreach ($headers as [$name, $values]) {
                $request = $request->withHeader($name, $values);
            }
        }

        // Create canonical request.
        $canonicalRequest = $this->createCanonicalRequest(
            $request,
            $contentHash,
            !empty($options['disable_double_encoding']),
        );

        // Create string to sign.
        $credentialScope = $this->createCredentialScope($date);
        $stringToSign = $this->createStringToSign($dateTime, $credentialScope, $canonicalRequest);

        // Calculate signature.
        $signingKey = $this->createSigningKey($credentials->getSecretAccessKey(), $date);
        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

        // Create authorization header.
        $signedHeaders = $this->getSignedHeadersString($request);
        $authorizationHeader = sprintf(
            '%s Credential=%s/%s, SignedHeaders=%s, Signature=%s',
            self::ALGORITHM,
            $credentials->getAccessKeyId(),
            $credentialScope,
            $signedHeaders,
            $signature,
        );

        if ($request instanceof Request) {
            $request = $request->withNormalizedHeaders([
                'authorization' => [
                    'Authorization',
                    [$authorizationHeader],
                ],
            ]);
        } else {
            $request = $request->withHeader(
                'Authorization',
                $authorizationHeader
            );
        }

        return new SignerResult(
            new HttpTransportRequest($request),
            $signature
        );
    }

    /**
     * Presign a PSR-7 request for use as a pre-signed URL.
     *
     * @param int $expires Expiration time in seconds (max 604800 = 7 days).
     * @param array{
     *     timestamp?: int,
     *     disable_double_encoding?: bool,
     * } $options
     */
    public function presignRequest(
        RequestInterface $request,
        AwsCredentialsIdentityInterface $credentials,
        int $expires,
        array $options = [],
    ): RequestInterface
    {
        $expires = min($expires, 604800); // AWS maximum is 7 days.
        $timestamp = $options['timestamp'] ?? time();
        $dateTime = gmdate('Ymd\THis\Z', $timestamp);
        $date = gmdate('Ymd', $timestamp);

        $uri = $request->getUri();
        $query = $this->parseQueryString($uri->getQuery());

        // Add required query parameters.
        $query['X-Amz-Algorithm'] = self::ALGORITHM;
        $query['X-Amz-Credential'] = sprintf(
            '%s/%s',
            $credentials->getAccessKeyId(),
            $this->createCredentialScope($date),
        );
        $query['X-Amz-Date'] = $dateTime;
        $query['X-Amz-Expires'] = (string) $expires;
        $query['X-Amz-SignedHeaders'] = $this->getSignedHeadersString($request);

        $sessionToken = $credentials->getSessionToken();
        if ($sessionToken !== null) {
            $query['X-Amz-Security-Token'] = $sessionToken;
        }

        // Update request with new query parameters (without signature).
        $uri = $uri->withQuery($this->buildQueryString($query));
        $request = $request->withUri($uri);

        // Create canonical request for presigned URL — payload is unsigned.
        $canonicalRequest = $this->createCanonicalRequest(
            $request,
            'UNSIGNED-PAYLOAD',
            !empty($options['disable_double_encoding']),
        );

        // Create string to sign.
        $credentialScope = $this->createCredentialScope($date);
        $stringToSign = $this->createStringToSign($dateTime, $credentialScope, $canonicalRequest);

        // Calculate signature.
        $signingKey = $this->createSigningKey($credentials->getSecretAccessKey(), $date);
        $signature = hash_hmac('sha256', $stringToSign, $signingKey);

        // Add signature to query parameters.
        $query['X-Amz-Signature'] = $signature;
        $uri = $uri->withQuery($this->buildQueryString($query));

        return $request->withUri($uri);
    }

    /**
     * @param array{
     *     unsigned_payload?: bool,
     *     streaming_unsigned_trailer?: bool,
     * } $options
     */
    private function getContentHash(
        RequestInterface $request,
        array $options,
    ): string
    {
        if (!empty($options['streaming_unsigned_trailer'])) {
            return AwsChunkedTrailer::STREAMING_UNSIGNED_PAYLOAD_TRAILER;
        }

        if (!empty($options['unsigned_payload'])) {
            return 'UNSIGNED-PAYLOAD';
        }

        if ($request->hasHeader('X-Amz-Content-Sha256')) {
            return $request->getHeaderLine('X-Amz-Content-Sha256');
        }

        $body = $request->getBody();
        if ($body instanceof RequestStreamInterface) {
            if (!$body->isAvailable()) {
                throw new \RuntimeException(
                    'Cannot calculate a SigV4 payload hash for an unavailable '
                    . 'request body.'
                );
            }

            if (!$body->isReplayable() && !$body->isSeekable()) {
                throw new \RuntimeException(
                    'Cannot calculate a SigV4 payload hash for a non-seekable '
                    . 'request body.'
                );
            }

            return $body->hash();
        }

        if (!$body->isSeekable()) {
            throw new \RuntimeException(
                'Cannot calculate a SigV4 payload hash for a non-seekable '
                . 'request body.'
            );
        }

        return StreamBodyAdapter::wrap($body)->hash();
    }

    private function createCanonicalRequest(
        RequestInterface $request,
        string $contentHash,
        bool $disableDoubleEncoding = false,
    ): string
    {
        $uri = $request->getUri();

        $canonicalUri = $this->createCanonicalUri(
            $uri,
            $disableDoubleEncoding
        );
        $canonicalQueryString = $this->createCanonicalQueryString($uri);
        [$canonicalHeaders, $signedHeaders] = $this->createCanonicalHeaders($request);

        return implode("\n", [
            $request->getMethod(),
            $canonicalUri,
            $canonicalQueryString,
            $canonicalHeaders,
            $signedHeaders,
            $contentHash,
        ]);
    }

    private function createCanonicalUri(
        UriInterface $uri,
        bool $disableDoubleEncoding
    ): string
    {
        $path = $uri->getPath();
        if ($path === '') {
            return '/';
        }

        // The sent path is already percent-encoded once; sign it as sent.
        if ($disableDoubleEncoding) {
            return $path;
        }

        // Normalize path segments (collapse . and .., percent-encode).
        $segments = explode('/', $path);
        $normalizedSegments = [];
        foreach ($segments as $segment) {
            if ($segment === '..') {
                array_pop($normalizedSegments);
            } elseif ($segment !== '' && $segment !== '.') {
                $normalizedSegments[] = rawurlencode($segment);
            }
        }

        $canonicalPath = '/' . implode('/', $normalizedSegments);

        // Preserve trailing slash if present in original.
        if (str_ends_with($path, '/') && !str_ends_with($canonicalPath, '/')) {
            $canonicalPath .= '/';
        }

        return str_replace('%2F', '/', $canonicalPath);
    }

    private function createCanonicalQueryString(UriInterface $uri): string
    {
        $query = $this->parseQueryString($uri->getQuery());
        if ($query === []) {
            return '';
        }

        ksort($query);

        $canonical = [];
        foreach ($query as $key => $value) {
            if ($key === 'X-Amz-Signature') {
                continue; // Skip signature for presigned URLs.
            }
            $canonicalKey = rawurlencode((string) $key);
            if (is_array($value)) {
                sort($value);
                foreach ($value as $v) {
                    $canonical[] = $canonicalKey . '=' . rawurlencode((string) $v);
                }
            } else {
                $canonical[] = $canonicalKey . '=' . rawurlencode((string) $value);
            }
        }

        return implode('&', $canonical);
    }

    /**
     * @return array{0: string, 1: string} `[canonicalHeadersBlock, signedHeadersList]`
     */
    private function createCanonicalHeaders(
        RequestInterface $request,
    ): array
    {
        $headers = [];

        foreach ($request->getHeaders() as $name => $values) {
            $name = strtolower($name);
            if (in_array($name, $this->unsignableHeaders, true)) {
                continue;
            }
            // Combine multiple header values and collapse whitespace.
            $value = implode(',', array_map('trim', $values));
            $value = preg_replace('/\s+/', ' ', $value);
            $headers[$name] = $name . ':' . $value;
        }

        ksort($headers);

        $canonicalHeaders = implode("\n", $headers) . "\n";
        $signedHeaders = implode(';', array_keys($headers));

        return [$canonicalHeaders, $signedHeaders];
    }

    private function getSignedHeadersString(
        RequestInterface $request,
    ): string
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $name = strtolower($name);
            if (!in_array($name, $this->unsignableHeaders, true)) {
                $headers[] = $name;
            }
        }
        sort($headers);
        return implode(';', $headers);
    }

    private function createCredentialScope(string $date): string
    {
        return sprintf(
            '%s/%s/%s/%s',
            $date,
            $this->region,
            $this->service,
            self::TERMINATOR,
        );
    }

    private function createStringToSign(
        string $dateTime,
        string $credentialScope,
        string $canonicalRequest,
    ): string
    {
        return implode("\n", [
            self::ALGORITHM,
            $dateTime,
            $credentialScope,
            hash('sha256', $canonicalRequest),
        ]);
    }

    private function createSigningKey(string $secretKey, string $date): string
    {
        $kSecret = 'AWS4' . $secretKey;
        $kDate = hash_hmac('sha256', $date, $kSecret, true);
        $kRegion = hash_hmac('sha256', $this->region, $kDate, true);
        $kService = hash_hmac('sha256', $this->service, $kRegion, true);
        return hash_hmac('sha256', self::TERMINATOR, $kService, true);
    }

    /**
     * @return array<array-key, mixed> Numeric names such as `1` become int keys.
     */
    private function parseQueryString(string $query): array
    {
        if ($query === '') {
            return [];
        }
        $result = [];
        parse_str($query, $result);
        return $result;
    }

    /**
     * @param array<string, mixed> $params
     */
    private function buildQueryString(array $params): string
    {
        if ($params === []) {
            return '';
        }
        $parts = [];
        foreach ($params as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    $parts[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $v);
                }
            } else {
                $parts[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $value);
            }
        }
        return implode('&', $parts);
    }
}
