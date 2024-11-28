package org.kienlc.apigateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;

@Configuration
public class RememberMe {
    AbstractAuthenticationProcessingFilter authenticationFilter;

    @Bean
    RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
        TokenBasedRememberMeServices.RememberMeTokenAlgorithm encodingAlgorithm = TokenBasedRememberMeServices.RememberMeTokenAlgorithm.SHA256;
        TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices("myKey", userDetailsService, encodingAlgorithm);
        rememberMe.setMatchingAlgorithm(TokenBasedRememberMeServices.RememberMeTokenAlgorithm.MD5);

        authenticationFilter.setRememberMeServices(rememberMe);
        return rememberMe;
    }

    @Bean
    RememberMeAuthenticationFilter rememberMeFilter(AuthenticationManager authenticationManager, RememberMeServices rememberMeServices) {
        return new RememberMeAuthenticationFilter(authenticationManager, rememberMeServices);
    }

    @Bean
    TokenBasedRememberMeServices rememberMeService(UserDetailsService userDetailsService) {
        return new TokenBasedRememberMeServices("springRocks", userDetailsService);
    }

    @Bean
    RememberMeAuthenticationProvider rememberMeAuthenticationProvider() {
        return new RememberMeAuthenticationProvider("springRocks");
    }


}
