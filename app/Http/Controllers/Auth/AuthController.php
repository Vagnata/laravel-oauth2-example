<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Partner;
use App\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $request->validate([
            'email'    => 'required|string|email',
            'password' => 'required|string'
        ]);
        $credentials = request(['email', 'password']);

        if (!Auth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $user        = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        $token       = $tokenResult->token;
        $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();

        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type'   => 'Bearer',
            'expires_at'   => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        ]);
    }

    public function loginByPartner(Request $request)
    {
        $request->validate(['partner-token' => 'required|string']);

        $partnerData = config('integrators.' . $request->get('partner-token'));

        if (is_null($partnerData)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        $partner     = new Partner($partnerData);
        $tokenResult = User::createTokenByPartner($partner);
        $token       = $tokenResult->token;
        $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();

        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type'   => 'Bearer',
            'expires_at'   => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        ]);
    }

    public function register(Request $request)
    {
        $request->validate([
            'fName'    => 'required|string',
            'lName'    => 'required|string',
            'email'    => 'required|string|email|unique:users',
            'password' => 'required|string'
        ]);

        User::createByRequest($request);

        return response()->json(['message' => 'Successfully created user!'], 201);
    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();

        return response()->json(['message' => 'Successfully logged out']);
    }

    public function user(Request $request)
    {
        return response()->json($request->user());
    }
}
