<?php namespace LucaDegasperi\OAuth2Server\Middleware;

use League\OAuth2\Server\Exception\ClientException;
use AuthorizationServer;
use Closure, Exception;
use Response, Session;

class CheckAuthorizationParamsMiddleware
{
    /**
     * Run the check authorization params filter
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        try {
            $params = AuthorizationServer::checkAuthorizeParams();
            Session::put('authorize-params', $params);
        }
        catch (ClientException $e) {
            return Response::json([
                'status'        => 400,
                'error'         => 'bad_request',
                'error_message' => $e->getMessage(),
            ], 400);
        }
        catch (Exception $e) {
            return Response::json([
                'status'        => 500,
                'error'         => 'internal_server_error',
                'error_message' => 'Internal Server Error',
            ], 500);
        }
        
        return $next($request);
    }
}
