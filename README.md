# Smithy PHP Auth

Identities, identity resolvers with caching, auth schemes, and request signers
for Smithy PHP, including HTTP bearer token auth and AWS Signature Version 4
under `Aws/`. Requires PHP 8.2 or later.

This repository is a read-only split of
[smithy-lang/smithy-php](https://github.com/smithy-lang/smithy-php). Send
issues and pull requests to the monorepo.

## Installation

```shell
composer require smithy/auth
```

## Signing a Request

```php
use Smithy\Auth\Aws\AwsCredentials;
use Smithy\Auth\Aws\SigV4Signer;
use Smithy\Http\Message\HttpTransportRequest;
use Smithy\Http\Message\Request;

$signer = new SigV4Signer('s3', 'us-east-1');
$result = $signer->sign(
    new HttpTransportRequest(
        new Request('GET', 'https://example.s3.us-east-1.amazonaws.com/')
    ),
    new AwsCredentials('AKIDEXAMPLE', 'secret-example-key')
);

echo $result->signedRequest->request->getHeaderLine('Authorization');
```

## Components

| Component | Responsibility |
|---|---|
| `IdentityInterface`, `BearerToken`, `AnonymousIdentity` | Who is calling |
| `IdentityResolverInterface`, `IdentityResolvers` | Look up an identity by its class |
| `CachingIdentityResolver` | Caches identities and refreshes them before they expire |
| `IdentityChain`, `StaticTokenProvider` | Chain resolvers or serve a fixed token |
| `AuthSchemeInterface`, `HttpBearerAuthScheme`, `NoAuthScheme` | Pair an identity resolver with a signer |
| `SignerInterface`, `HttpBearerAuthSigner`, `NullSigner` | Add auth to a request |
| `Aws\SigV4AuthScheme`, `Aws\SigV4Signer`, `Aws\SignatureV4` | AWS Signature Version 4 |
| `Aws\AwsCredentials`, `Aws\StaticCredentialProvider` | AWS credentials and a fixed provider |
| `Aws\AwsChunkedRequestStream`, `Aws\AwsChunkedTrailer` | Chunked streaming signatures with trailers |

## Dependencies

This package builds on `smithy/core` and `smithy/http`.

## Design

See [Auth Runtime Design](https://github.com/smithy-lang/smithy-php/blob/main/docs/design/auth/auth-runtime-design.md).

## Contributing

Run the component tests from the monorepo root:

```shell
vendor/bin/phpunit tests/Auth
```
