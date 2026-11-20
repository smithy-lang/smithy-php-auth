<?php

/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

declare(strict_types=1);

namespace Smithy\Auth\Aws;

use Smithy\Core\Checksum\Checksum;
use Smithy\Core\Checksum\ChecksumAlgorithm;
use Smithy\Http\Message\RequestStreamInterface;

/**
 * Encode a request body as `aws-chunked` with a trailing checksum field.
 *
 * The encoded body is the unsigned-trailer layout from the flexible-checksums
 * SEP, produced as body bytes:
 *
 * ```
 * <hex-chunk-size>\r\n<chunk-bytes>\r\n   (one per chunk)
 * 0\r\n
 * x-amz-checksum-<algo>:<base64-checksum>\r\n
 * \r\n
 * ```
 *
 * Every chunk except the last carries exactly `$chunkSize` payload bytes. The
 * checksum is computed incrementally as the payload is read, so the payload is
 * read once and is never buffered whole. After a retry rewind the stream
 * writes the checksum from the first completed attempt, as the SEP requires.
 */
final class AwsChunkedRequestStream implements RequestStreamInterface
{
    public const DEFAULT_CHUNK_SIZE = 65536;

    private const CRLF = "\r\n";

    private Checksum $hasher;

    private string $pending = '';

    private int $position = 0;

    private bool $trailerWritten = false;

    private ?string $checksum = null;

    private ?string $retryChecksum = null;

    public function __construct(
        private readonly RequestStreamInterface $inner,
        private readonly ChecksumAlgorithm $algorithm,
        private readonly int $chunkSize = self::DEFAULT_CHUNK_SIZE,
    ) {
        if ($chunkSize < 1) {
            throw new \InvalidArgumentException(
                'The aws-chunked chunk size must be at least 1 byte.'
            );
        }

        $this->hasher = $algorithm->create();
    }

    /**
     * Return the trailer field name, such as `x-amz-checksum-crc32`.
     */
    public function trailerName(): string
    {
        return self::headerName($this->algorithm);
    }

    /**
     * Return the payload length before encoding, for
     * `x-amz-decoded-content-length`, or null when it is unknown.
     */
    public function decodedContentLength(): ?int
    {
        return $this->inner->length();
    }

    /**
     * Return the base64 trailer checksum once the trailer has been written.
     */
    public function checksum(): ?string
    {
        return $this->checksum;
    }

    /**
     * Return the full encoded body.
     */
    public function __toString(): string
    {
        if ($this->started() && $this->isReplayable()) {
            $this->rewindForRetry();
        }

        return $this->getContents();
    }

    public function close(): void
    {
        $this->inner->close();
    }

    public function detach()
    {
        return $this->inner->detach();
    }

    public function getSize(): ?int
    {
        return $this->length();
    }

    /**
     * Return the encoded body length when the payload length is known.
     */
    public function length(): ?int
    {
        $decoded = $this->decodedContentLength();
        if ($decoded === null) {
            return null;
        }

        $fullChunks = \intdiv($decoded, $this->chunkSize);
        $remainder = $decoded % $this->chunkSize;
        $length = $fullChunks * self::chunkFrameLength($this->chunkSize);
        if ($remainder > 0) {
            $length += self::chunkFrameLength($remainder);
        }

        return $length + \strlen($this->trailerBlock(
            \str_repeat('A', self::encodedDigestLength($this->algorithm))
        ));
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        return $this->trailerWritten && $this->pending === '';
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new \RuntimeException(
            'aws-chunked request bodies rewind through rewindForRetry().'
        );
    }

    public function rewind(): void
    {
        $this->rewindForRetry();
    }

    /**
     * Rewind the payload and restart encoding, keeping the checksum from the
     * first completed attempt for the trailer.
     */
    public function rewindForRetry(): void
    {
        $this->inner->rewindForRetry();
        $this->retryChecksum ??= $this->checksum;
        $this->hasher = $this->algorithm->create();
        $this->pending = '';
        $this->position = 0;
        $this->trailerWritten = false;
        $this->checksum = null;
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new \RuntimeException(
            'aws-chunked request bodies are read-only.'
        );
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        if ($length < 0) {
            throw new \InvalidArgumentException(
                'Read length must be non-negative.'
            );
        }

        while (\strlen($this->pending) < $length && !$this->trailerWritten) {
            $this->encodeNextChunk();
        }

        $bytes = \substr($this->pending, 0, $length);
        $this->pending = \substr($this->pending, \strlen($bytes));
        $this->position += \strlen($bytes);

        return $bytes;
    }

    public function getContents(): string
    {
        $contents = '';
        while (!$this->eof()) {
            $contents .= $this->read($this->chunkSize + 64);
        }

        return $contents;
    }

    public function getMetadata(?string $key = null)
    {
        return $this->inner->getMetadata($key);
    }

    /**
     * Hash the encoded body, replaying the payload from the retry start.
     */
    public function hash(string $algo = 'sha256', bool $raw = false): string
    {
        if (!$this->isReplayable()) {
            throw new \RuntimeException(
                'Hashing an aws-chunked body needs a replayable payload.'
            );
        }

        $this->rewindForRetry();
        $context = \hash_init($algo);
        while (!$this->eof()) {
            \hash_update($context, $this->read($this->chunkSize + 64));
        }
        $this->rewindForRetry();

        return \hash_final($context, $raw);
    }

    public function isReplayable(): bool
    {
        return $this->inner->isReplayable();
    }

    public function isAvailable(): bool
    {
        return $this->inner->isAvailable();
    }

    public function started(): bool
    {
        return $this->position > 0;
    }

    public function fullyConsumed(): bool
    {
        return $this->eof();
    }

    /**
     * Read up to one chunk of payload and append its frame; on payload EOF
     * append the terminating chunk and the trailer.
     */
    private function encodeNextChunk(): void
    {
        $chunk = '';
        while (\strlen($chunk) < $this->chunkSize) {
            $bytes = $this->inner->read($this->chunkSize - \strlen($chunk));
            if ($bytes === '') {
                break;
            }
            $chunk .= $bytes;
        }

        if ($chunk !== '') {
            $this->hasher->update($chunk);
            $this->pending .= \dechex(\strlen($chunk)) . self::CRLF
                . $chunk . self::CRLF;
        }

        if (\strlen($chunk) < $this->chunkSize || $this->inner->eof()) {
            $calculated = \base64_encode($this->hasher->digest());
            $this->checksum = $this->retryChecksum ?? $calculated;
            $this->pending .= $this->trailerBlock($this->checksum);
            $this->trailerWritten = true;
        }
    }

    private function trailerBlock(string $checksum): string
    {
        return '0' . self::CRLF
            . self::headerName($this->algorithm) . ':' . $checksum . self::CRLF
            . self::CRLF;
    }

    private static function chunkFrameLength(int $size): int
    {
        return \strlen(\dechex($size)) + $size + 2 * \strlen(self::CRLF);
    }

    /**
     * Return the AWS trailer header name for an algorithm, such as
     * `x-amz-checksum-crc32`. The `x-amz-checksum-` prefix is AWS-specific and
     * owned here rather than by the algorithm.
     */
    private static function headerName(ChecksumAlgorithm $algorithm): string
    {
        return 'x-amz-checksum-' . \strtolower($algorithm->value);
    }

    private static function encodedDigestLength(
        ChecksumAlgorithm $algorithm
    ): int
    {
        return 4 * \intdiv($algorithm->digestLength() + 2, 3);
    }
}
