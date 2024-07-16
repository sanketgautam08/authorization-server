package com.sanketgautam.authorirzation.server.service;


import com.sanketgautam.authorirzation.server.model.Client;
import com.sanketgautam.authorirzation.server.repo.ClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

@Service
public class CustomRegisteredClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    public CustomRegisteredClientService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id).orElseThrow(() -> new NoSuchElementException("No client with id " + id));
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId).orElseThrow(() -> new NoSuchElementException("Invalid Client ID: " + clientId));
    }
}
