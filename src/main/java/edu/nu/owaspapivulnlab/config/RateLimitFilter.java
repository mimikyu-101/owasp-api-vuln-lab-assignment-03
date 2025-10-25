package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * FIX #5: Simple in-memory rate limiter to prevent abuse
 * Limits requests per IP address to prevent brute force and DoS attacks
 */
@Component
public class RateLimitFilter implements Filter {
    
    // FIX #5: Store request counts per IP address
    private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    
    // FIX #5: Configuration - allow 20 requests per minute per IP
    private static final int MAX_REQUESTS_PER_MINUTE = 20;
    private static final long WINDOW_SIZE_MS = 60_000; // 1 minute
    
    public RateLimitFilter() {
        // FIX #5: Reset counters every minute
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(
            () -> requestCounts.clear(),
            1, 1, TimeUnit.MINUTES
        );
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // FIX #5: Get client IP address
        String clientIp = getClientIp(httpRequest);
        
        // FIX #5: Get current request count for this IP
        AtomicInteger count = requestCounts.computeIfAbsent(clientIp, k -> new AtomicInteger(0));
        
        // FIX #5: Check if limit exceeded
        if (count.incrementAndGet() > MAX_REQUESTS_PER_MINUTE) {
            // FIX #5: Return 429 Too Many Requests
            httpResponse.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write(
                "{\"error\":\"rate_limit_exceeded\",\"message\":\"Too many requests. Please try again later.\"}"
            );
            return;
        }
        
        // FIX #5: Allow request to proceed
        chain.doFilter(request, response);
    }
    
    // FIX #5: Extract client IP, considering proxies
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}