<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{

    //function login
    public function login(Request $request)
    {
        //validation
        $this->validate($request, [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        //check if email user exist
        $email = $request->input('email');
        $password = $request->input('password');
        $user = User::where('email', $email)->first(); //select * from users where email = email

        if (!$user) {
            $out = [
                'status' => false,
                'msg' => 'Email not found',
                'code' => 401,
            ];
            return response()->json($out);
        }

        //check if password user exist
        if (Hash::check($password, $user->password)) {
            $check = Auth::attempt(['email' => $email, 'password' => $password]);
            $out = [
                'status' => true,
                'msg' => 'Login success',
                'code' => 200,
            ];
        } else {
            $out = [
                'status' => false,
                'msg' => 'Password not match',
                'code' => 401,
            ];
        }
        return response()->json($out);
    }

    //fnction register
    public function register(Request $request)
    {
        //validation
        $this->validate($request, [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:8'
        ]);

        //create user
        $email = $request->input('email');
        $name = $request->input('name');
        $password = $request->input('password');

        $hash = Hash::make($password);

        //array
        $data = [
            'name' => $name,
            'email' => $email,
            'email_verified_at' => now(),
            'password' => $hash,
        ];
        //response message json
        if (User::create($data)) {
            $out = [
                'status' => true,
                'message' => 'User created successfully',
                'code' => 201,
                $data,
            ];
        } else {
            $out = [
                'status' => false,
                'message' => 'User not created',
                'code' => 404,
            ];
        }
        //output
        return response()->json($out, $out['code']);
    }
}
