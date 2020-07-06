<?php


namespace App\Factories;


use Laravel\Passport\Passport;
use Laravel\Passport\PersonalAccessTokenFactory as LaravelPersonalAccessTokenFactory;
use Laravel\Passport\PersonalAccessTokenResult;
use RuntimeException;

class PersonalAccessTokenFactory extends LaravelPersonalAccessTokenFactory
{
    public function makeForPartner($name, array $scopes = [])
    {
        $clients  = $this->clients->personalAccessClient();

        if (is_null($clients)) {
            throw new RuntimeException('Personal access client not found. Please create one.');

        }

        $response = $this->dispatchRequestToAuthorizationServer(
            $this->createRequest($clients, null, $scopes)
        );

        $token = tap($this->findAccessToken($response), function ($token) use ($name) {
            $this->tokens->save($token->forceFill([
                'user_id' => null,
                'name' => $name,
            ]));
        });

        return new PersonalAccessTokenResult(
            $response['access_token'], $token
        );
    }
}
