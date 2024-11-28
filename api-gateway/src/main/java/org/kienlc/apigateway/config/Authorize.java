package org.kienlc.apigateway.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collection;
import java.util.function.Supplier;

@Configuration
public class Authorize {
//    AuthorizationManagers authorizationManager = new AuthorizationManagers();
//
//    SecurityFilterChain a = new SecurityFilterChain();

    Supplier<Authentication> supplier = () -> SecurityContextHolder.getContext().getAuthentication();


    GrantedAuthority ROLE_ADMIN = new SimpleGrantedAuthority("ROLE_ADMIN");

    @PreAuthorize(value = "hasRole('ADMIN')")
    public void adminOnlyMethod() {
        // Code for admins
    }

    @Bean
    static GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults("MYPREFIX_");
    }

    @Bean
    public SecurityFilterChain web(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .dispatcherTypeMatchers(DispatcherType.REQUEST, DispatcherType.ASYNC).denyAll()
                        .requestMatchers("/endpoint").hasAuthority("USER")
                        .requestMatchers(HttpMethod.GET, "/endpoint").hasAuthority("ADMIN")
                        .requestMatchers(RegexRequestMatcher.regexMatcher("/resource/[A-Za-z0-9]+")).denyAll()
                        .anyRequest().authenticated()
                );
        // ...

        return http.build();
    }


}
