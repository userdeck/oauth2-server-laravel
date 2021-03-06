<?php

class TestCase extends Orchestra\Testbench\TestCase {

    protected function getPackageProviders()
    {
        return ['LucaDegasperi\OAuth2Server\OAuth2ServerServiceProvider'];
    }

    protected function getPackageAliases()
    {
        return [
            'AuthorizationServer' => 'LucaDegasperi\OAuth2Server\Facades\AuthorizationServerFacade',
            'ResourceServer'  => 'LucaDegasperi\OAuth2Server\Facades\ResourceServerFacade',
        ];
    }

}
