package com.sanketgautam.authorirzation.server.model;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.Set;

public class Client extends RegisteredClient {
    private final String id;
    private final String clientId;
    private final String secret;
    private final Set<String> scopes;
    private final Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    private final Set<AuthorizationGrantType> authorizationGrantTypes;
    private final Set<String>  redirectUris;

    public Client(String id, String clientId, String secret, Set<String> scopes, Set<AuthorizationGrantType> authorizationGrantTypes, Set<ClientAuthenticationMethod> clientAuthenticationMethods, Set<String> redirectUris) {
        this.id = id;
        this.clientId = clientId;
        this.secret = secret;
        this.scopes = scopes;
        this.authorizationGrantTypes = authorizationGrantTypes;
        this.clientAuthenticationMethods = clientAuthenticationMethods;
        this.redirectUris = redirectUris;
    }

    public String getId() {
        return id;
    }


    public String getClientId() {
        return clientId;
    }


    public String getSecret() {
        return secret;
    }


    @Override
    public Set<String> getScopes() {
        return scopes;
    }


    @Override
    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }

    @Override
    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return authorizationGrantTypes;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

}
