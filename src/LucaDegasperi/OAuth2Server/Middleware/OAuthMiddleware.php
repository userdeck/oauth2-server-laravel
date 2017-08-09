<?php namespace LucaDegasperi\OAuth2Server\Middleware;

use ResourceServer;
use Config, Response;
use Closure;

class OAuthMiddleware
{
    /**
     * Run the oauth filter.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $scope
     * @return mixed
     */
    public function handle($request, Closure $next, $scope = null)
    {
        try {
            ResourceServer::isValid(Config::get('oauth2.http_headers_only'));
        }
        catch (\League\OAuth2\Server\Exception\InvalidAccessTokenException $e) {
            return Response::json([
                'status'        => 403,
                'error'         => 'forbidden',
                'error_message' => $e->getMessage(),
            ], 403);
        }

        if (! is_null($scope)) {
            $scopes = explode(',', $scope);

            foreach ($scopes as $s) {
                if (! ResourceServer::hasScope($s)) {
                    return Response::json([
                        'status'        => 403,
                        'error'         => 'forbidden',
                        'error_message' => 'Only access token with scope '.$s.' can use this endpoint',
                    ], 403);
                }
            }
        }
        
        return $next($request);
    }
}
