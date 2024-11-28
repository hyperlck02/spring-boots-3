package org.kienlc.apigateway.config;

import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ListeningSecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.*;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.DelegatingFilterProxy;

import java.util.Collection;
import java.util.List;

@Configuration
public class SecurityConfig  {
    private final String[] freeResourceUrls = {"/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**",
            "/swagger-resources/**", "/api-docs/**", "/aggregate/**", "/actuator/prometheus"};
    private FilterChainProxy filterChainProxy;
    private DelegatingFilterProxy delegatingFilterProxy;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, RememberMeServices rememberMeServices) throws Exception {
        RequestCache nullRequestCache = new NullRequestCache();
//        return httpSecurity.authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers(freeResourceUrls)
//                        .permitAll()
//                        .anyRequest()
//                        .authenticated())
//                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
////                .csrf(csrf -> csrf)
//                .oauth2Login(Customizer.withDefaults())
//                .oauth2Client(Customizer.withDefaults())
//                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
//                .build();

        return httpSecurity
                .authorizeHttpRequests(x -> x.requestMatchers(freeResourceUrls).permitAll().anyRequest().authenticated())
                .securityContext(x -> x.requireExplicitSave(true))
                .csrf(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults())
                .formLogin(x -> x.loginPage("/login"))
                .requestCache(x -> x.requestCache(nullRequestCache))
                .securityContext(x -> x.securityContextRepository(new DelegatingSecurityContextRepository(
                        new NullSecurityContextRepository(),
                        new HttpSessionSecurityContextRepository()
                )))
                .rememberMe((remember) -> remember
                        .rememberMeServices(rememberMeServices)
                )
                .sessionManagement(x ->
                        x.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                                .sessionFixation(y -> y.newSession()) // fix loi bao mat session fixation
                                .maximumSessions(1)
                                .maxSessionsPreventsLogin(true)
                                )
                .logout(x -> x.logoutUrl("/logout").permitAll())
                .build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.
        configuration.applyPermitDefaultValues();
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @PreAuthorize(value = "hasAuthority('ROLE_ADMIN')")
    public void test() {
        SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
        Authentication authentication = new TestingAuthenticationToken("username", "password", "ROLE_USER");

        emptyContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(emptyContext);
        SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy();


        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication1 = context.getAuthentication();
        String username = authentication.getName();
        Object principal = authentication.getPrincipal();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

//
//        AuthenticationEntryPoint authenticationEntryPoint = new AuthenticationEntryPoint();
//
//        AbstractAuthenticationProcessingFilter authenticationFilter = new AbstractAuthenticationProcessingFilter("/login") ;
//
//        AuthenticationFailureHandler authenticationFailureHandler = new AuthenticationFailureHandler();
//
//        AuthenticationManagerBuilder authenticationManagerBuilder = new AuthenticationManagerBuilder();
//
        SecurityContextPersistenceFilter securityContextPersistenceFilter = new SecurityContextPersistenceFilter();
//
//        BasicAuthenticationFilter basicAuthenticationFilter = new BasicAuthenticationFilter(authenticationManager) ;

        UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter = new UsernamePasswordAuthenticationFilter();
//
//        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
//
//        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, "password", authorities);

        SecurityContextRepository securityContextRepository = new DelegatingSecurityContextRepository();
    }

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .passwordEncoder(x -> passwordEncoder().encode("password"))
                .roles("ROLE_USER")

                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);


        return new ProviderManager(authenticationProvider);
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder builder) {
        builder.eraseCredentials(false);

    }

}
