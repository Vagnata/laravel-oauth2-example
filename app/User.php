<?php

namespace App;

use Illuminate\Http\Request;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;

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
}
