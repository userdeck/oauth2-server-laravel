<?php namespace LucaDegasperi\OAuth2Server\Middleware;

use ResourceServer;
use Response;
use Closure;

class OAuthOwnerMiddleware
{
    /**
     * Run the oauth owner filter
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $scope
     * @return mixed
     */
    public function handle($request, Closure $next, $scope = null)
    {
        if (! is_null($scope) && ResourceServer::getOwnerType() !== $scope) {
            return Response::json([
                'status'        => 403,
                'error'         => 'forbidden',
                'error_message' => 'Only access tokens representing '.$scope.' can use this endpoint',
            ], 403);
        }
        
        return $next($request);
    }
}
