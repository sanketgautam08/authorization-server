package com.sanketgautam.authorirzation.server.repo;

import com.sanketgautam.authorirzation.server.model.Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class ClientRepository{

    private final Logger LOGGER = LoggerFactory.getLogger(ClientRepository.class);
    private final JdbcClient jdbcClient;

    public ClientRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<RegisteredClient> findByClientId(String clientId) {
        String sql = """
            SELECT * FROM clients WHERE client_id = ?
        """;
        return getClientInfo(sql, clientId);
    }

    public Optional<RegisteredClient> findById(String id){
        String sql = """
                SELECT * FROM clients WHERE id = ?
                """;
        return getClientInfo(sql, id);
    }

    private Optional<RegisteredClient> getClientInfo(String sql, String param){
        try{
            Optional<Client> clientInfo =  Optional.of(jdbcClient.sql(sql).param(param).query(rowMapper).single());
            return Optional.ofNullable(mapClientToRegisteredClient(clientInfo.get()));
        }catch(EmptyResultDataAccessException e){
            LOGGER.info("No client with id/client_id {} found", param);
            return Optional.empty();
        }
    }

    private RegisteredClient mapClientToRegisteredClient(Client clientInfo){
        return RegisteredClient
                .withId(clientInfo.getId())
                .clientId(clientInfo.getClientId())
                .clientSecret(clientInfo.getSecret())
                .clientAuthenticationMethods(am -> am.addAll(clientInfo.getClientAuthenticationMethods()))
                .scopes(s -> s.addAll(clientInfo.getScopes()))
                .redirectUris(ru -> ru.addAll(clientInfo.getRedirectUris()))
                .authorizationGrantTypes(agt -> agt.addAll(clientInfo.getAuthorizationGrantTypes()))
                .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(30)).build())
                .build();
    }

    private final RowMapper<Client> rowMapper = (rs, rowNum) ->
        new Client(
                rs.getString("id"),
                rs.getString("client_id"),
                rs.getString("secret"),
                Arrays.stream(rs.getString("scope").split(",")).collect(Collectors.toSet()),
                Arrays.stream(rs.getString("grant_type").split(",")).map(AuthorizationGrantType::new).collect(Collectors.toSet()),
                Arrays.stream(rs.getString("auth_method").split(",")).map(ClientAuthenticationMethod::new).collect(Collectors.toSet()),
                Arrays.stream(rs.getString("redirect_uri").split(",")).collect(Collectors.toSet())
        );
    }