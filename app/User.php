<?php

namespace App;

use Illuminate\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;
use Laravel\Passport\Passport;
use Laravel\Passport\PersonalAccessTokenResult;

/**
 * @property mixed first_name
 * @property mixed last_name
 * @property mixed email
 * @property mixed|string password
 */
class User extends Authenticatable
{
    use HasApiTokens, Notifiable;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];
    protected $hidden = [
        'password',
        'remember_token',
    ];
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    public static function createByRequest(Request $request): User
    {
        $user             = new User;
        $user->first_name = $request->fName;
        $user->last_name  = $request->lName;
        $user->email      = $request->email;
        $user->password   = bcrypt($request->password);
        $user->save();

        return $user;
    }

    public static function createTokenByPartner(Partner $partner): PersonalAccessTokenResult
    {
        Passport::$personalAccessClientId = $partner->clientId;
        $tokenFactory  = Container::getInstance()->make(\App\Factories\PersonalAccessTokenFactory::class);
        $personalToken = $tokenFactory->makeForPartner($partner->name, []);

        return $personalToken;
    }
}
