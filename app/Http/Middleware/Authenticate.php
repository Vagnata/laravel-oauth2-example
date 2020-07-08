<?php

namespace App\Http\Middleware;

use Closure;
use http\Exception\BadMethodCallException;
use http\Exception\InvalidArgumentException;
use http\Exception\RuntimeException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Illuminate\Config\Repository as Config;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Laminas\Diactoros\UploadedFileFactory;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

class Authenticate extends Middleware
{
    public function handle($request, Closure $next, ...$guards)
    {
        if ($this->authenticate($request, $guards)) {
            return $next($request);
        }

        throw new AuthenticationException('Unauthorized');
    }

    protected function authenticate($request, array $guards): bool
    {
        $symfonyRequest = $this->createCompatibleSymfonyRequest($request);

        $psrValidatedRequest = $this->validateAuthorization($symfonyRequest);
        $this->hasActiveClient($psrValidatedRequest);

        return true;
    }

    private function validateAuthorization(ServerRequestInterface $request)
    {
        if ($request->hasHeader('authorization') === false) {
            throw OAuthServerException::accessDenied('Missing "Authorization" header');
        }

        $header = $request->getHeader('authorization');
        $jwt = \trim((string) \preg_replace('/^(?:\s+)?Bearer\s/', '', $header[0]));

        try {
            // Attempt to parse and validate the JWT
            $token    = (new Parser())->parse($jwt);
            $cryptKey = $this->makeCryptKey();
            try {
                if ($token->verify(new Sha256(), $cryptKey->getKeyPath()) === false) {
                    throw OAuthServerException::accessDenied('Access token could not be verified');
                }
            } catch (BadMethodCallException $exception) {
                throw OAuthServerException::accessDenied('Access token is not signed', null, $exception);
            }

            // Ensure access token hasn't expired
            $data = new ValidationData();
            $data->setCurrentTime(\time());

            if ($token->validate($data) === false) {
                throw OAuthServerException::accessDenied('Access token is invalid');
            }
        } catch (InvalidArgumentException $exception) {
            // JWT couldn't be parsed so return the request as is
            throw OAuthServerException::accessDenied($exception->getMessage(), null, $exception);
        } catch (RuntimeException $exception) {
            // JWT couldn't be parsed so return the request as is
            throw OAuthServerException::accessDenied('Error while decoding to JSON', null, $exception);
        }

        // Check if token has been revoked
        if ($this->isTokenRevoked($token->getClaim('jti'))) {
            throw OAuthServerException::accessDenied('Access token has been revoked');
        }

        // Return the request with additional attributes
        return $request
            ->withAttribute('oauth_access_token_id', $token->getClaim('jti'))
            ->withAttribute('oauth_client_id', $token->getClaim('aud'))
            ->withAttribute('oauth_user_id', $token->getClaim('sub'))
            ->withAttribute('oauth_scopes', $token->getClaim('scopes'));
    }

    private function makeCryptKey()
    {
        $key = str_replace('\\n', "\n", app()->make(Config::class)->get('passport.public_key'));

        if (! $key) {
            $key = 'file://'.Passport::keyPath('oauth-public.key');
        }

        return new CryptKey($key, null, false);
    }

    private function isTokenRevoked($id)
    {
        $accessToken = Passport::token()->where('id', $id)->first();

        if ($accessToken) {
            return $accessToken->revoked;
        }

        return true;
    }

    private function createCompatibleSymfonyRequest(\Illuminate\Http\Request $request): ServerRequestInterface
    {
        $psrHttpFactory = new PsrHttpFactory(
            new ServerRequestFactory,
            new StreamFactory,
            new UploadedFileFactory,
            new ResponseFactory
        );

        return $psrHttpFactory->createRequest($request);
    }

    private function hasActiveClient(ServerRequestInterface $psrRequest)
    {
        $model = Passport::client();
        $client = $model->where('id', $psrRequest->getAttribute('oauth_client_id'))->first();

        if (!$client) {
            throw new AuthenticationException('Client of the token not found');
        }

        if ($client->revoked) {
            throw new AuthenticationException('Client inactive');
        }

        return true;
    }
}
