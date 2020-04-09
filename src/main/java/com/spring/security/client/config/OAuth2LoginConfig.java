package com.spring.security.client.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@EnableOAuth2Client
@Configuration
public class OAuth2LoginConfig {
    @EnableWebSecurity
    public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests(authorize -> authorize
                            .anyRequest().authenticated()
                    )
                    .oauth2Login();
        }

   /*     @Bean
        public ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(this.getClientRegistration());
        }

        public ClientRegistration getClientRegistration(){
            return ClientRegistration.withRegistrationId("A")
                    .clientId("client")
                    .clientName("client")
                    .clientSecret("123456")
                    .scope("all")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                    .redirectUriTemplate("http://127.0.0.1:8081/login/oauth2/code/A")
                    .authorizationUri("http://localhost:8080/oauth/authorize")
                    .tokenUri("http://localhost:8080/oauth/access_token")
                    .build();

        }*/
    }
}
