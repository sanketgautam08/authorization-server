package com.sanketgautam.authorirzation.server.repo;

import com.sanketgautam.authorirzation.server.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
public class UserRepository {

    private final JdbcClient jdbcClient;
    private final Logger LOGGER = LoggerFactory.getLogger(UserRepository.class);


    public UserRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public Optional<User> findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = :username";
        try{
            return Optional.of(jdbcClient.sql(sql).params(Map.of("username", username)).query(User.class).single());
        }catch(EmptyResultDataAccessException e){
            LOGGER.info("Username not found: {}", username);
            return Optional.empty();
        }

    }


}
