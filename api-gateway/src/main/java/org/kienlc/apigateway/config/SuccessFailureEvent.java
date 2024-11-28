package org.kienlc.apigateway.config;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SuccessFailureEvent {
    static Map<String, Integer> map = new ConcurrentHashMap<>();
    static Integer a = 5;


    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        System.out.println("Login success for user: " + event.getAuthentication().getName());
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        System.out.println("Login failed: Bad credentials for user: " +
                event.getAuthentication().getPrincipal());
    }
}
