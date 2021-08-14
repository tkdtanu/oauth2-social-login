package com.tkd.oauth2;

import com.tkd.oauth2.properties.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class OAuth2PocApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuth2PocApplication.class, args);
	}

}
