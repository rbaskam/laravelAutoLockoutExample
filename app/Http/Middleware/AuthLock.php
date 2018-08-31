<?php

namespace App\Http\Middleware;

use Closure;

class AuthLock
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (!request()->user()) {
            return $next($request);
        }

        if (!request()->user()->hasLockoutTime()) {
            if(session('lock-expires-at')) {
                session()->forget('lock-expires-at');
            }

            return $next($request);

        }

        if ($lockExpiresAt = session('lock-expires-at')) {
            if ($lockExpiresAt < now()) {
                return redirect()->route('login.locked');
            }
        }

        session(['lock-expires-at' => now()->addMinutes($request->user()->getLockoutTime())]);

        return $next($request);
        
    }
}
