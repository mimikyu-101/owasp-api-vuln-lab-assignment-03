package edu.nu.owaspapivulnlab.config;

import edu.nu.owaspapivulnlab.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    private final RateLimitFilter rateLimitFilter;  // FIX #5: Inject rate limiter
    private final JwtService jwtService;              // FIX #7: Inject JWT service

    // FIX #5: Constructor to inject dependencies
    public SecurityConfig(RateLimitFilter rateLimitFilter, JwtService jwtService) {
        this.rateLimitFilter = rateLimitFilter;
        this.jwtService = jwtService;
    }

    // VULNERABILITY(API7 Security Misconfiguration): overly permissive CORS/CSRF and antMatchers order
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable()); // APIs typically stateless; but add CSRF for state-changing in real apps
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
                .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
                // FIX #2: Remove overly permissive GET access - require authentication for all API endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()  // FIX #2: Require authentication for all /api/** endpoints
                .anyRequest().authenticated()
        );

        http.headers(h -> h.frameOptions(f -> f.disable())); // allow H2 console

        http.addFilterBefore(new JwtFilter(jwtService), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        
        // FIX #5: Add rate limiting filter to prevent brute force and DoS attacks
        http.addFilterBefore(rateLimitFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // FIX #1: Add BCrypt password encoder for secure password hashing
    // BCrypt automatically handles salting and uses adaptive hashing to prevent rainbow table attacks
    // FIX #7: Use JwtService for token validation
    @Bean
    public org.springframework.security.crypto.password.PasswordEncoder passwordEncoder() {
        return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
    }

    // FIX #7: Secure JWT filter with proper validation using JwtService
    static class JwtFilter extends OncePerRequestFilter {
        private final JwtService jwtService;
        JwtFilter(JwtService jwtService) { 
            this.jwtService = jwtService; 
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
                try {
                    // FIX #7: Use JwtService for validation (includes issuer/audience checks)
                    if (jwtService.validate(token)) {
                        String user = jwtService.extractUsername(token);
                        String role = jwtService.extractRole(token);  // FIX #7: Extract role using JwtService
                        
                        UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(
                                user, 
                                null,
                                role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList()
                        );
                        SecurityContextHolder.getContext().setAuthentication(authn);
                    }
                } catch (Exception e) {
                    // FIX #7: Log but don't expose error details to client
                    // Token validation failed, continue as unauthenticated
                }
            }
            chain.doFilter(request, response);
        }
    }
}
