package com.sanketgautam.authorirzation.server;

import com.sanketgautam.authorirzation.server.config.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RsaKeyProperties.class)
@SpringBootApplication
public class AuthorirzationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorirzationServerApplication.class, args);
	}

}
