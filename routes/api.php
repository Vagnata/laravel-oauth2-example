<?php

use Illuminate\Support\Facades\Route;

Route::group([
    'prefix' => 'auth'
], function () {
    Route::post('login', 'Auth\AuthController@login')->name('login');
    Route::post('loginPartner', 'Auth\AuthController@loginByPartner');
    Route::post('register', 'Auth\AuthController@register');

    Route::group([
        'middleware' => 'auth:api'
    ], function () {
        Route::get('logout', 'Auth\AuthController@logout');
        Route::get('user', 'Auth\AuthController@user');
    });
});
