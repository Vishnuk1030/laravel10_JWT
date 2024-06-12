<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function register(Request $request)
    {

        $validation = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|string|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if ($validation->fails()) {
            return response()->json($validation->errors()->toJson(), 404);
        } else {
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);
            return response()->json([
                'message' => 'User SuccessFully Regsitered',
                'user' => $user
            ], 200);
        }
    }

    public function login(Request $request)
    {
        $validation = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);
        if ($validation->fails()) {
            return response()->json($validation->errors(), 422);
        } else {
            if (!$token = auth()->attempt($validation->validated())) {
                return response()->json([
                    'error' => 'Unauthriozed'
                ], 401);
            }
            return $this->createNewToken($token);
        }
    }

    public function createNewToken($token)
    {
        return response()->json([
            'access Token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }

    public function profile()
    {
        return response()->json(auth()->user());
    }

    public function logout()
    {
        auth()->logout();
        return response()->json([
            'message' => 'User SuccessFully Logged out',
        ]);
    }
}
