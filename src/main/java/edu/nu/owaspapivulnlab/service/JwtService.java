package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.audience}")
    private String audience;

    // FIX #7: Secure JWT with strong key, shorter TTL, and issuer/audience validation
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + expiration))
                .setIssuer(issuer)           // FIX #7: Add issuer claim
                .setAudience(audience)       // FIX #7: Add audience claim
                .signWith(SignatureAlgorithm.HS256, secret.getBytes())
                .compact();
    }

    // FIX #7: Validate issuer and audience when verifying JWT
    public boolean validate(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(secret.getBytes())
                    .requireIssuer(issuer)       // FIX #7: Validate issuer
                    .requireAudience(audience)   // FIX #7: Validate audience
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // FIX #7: Extract username from token with validation
    public String extractUsername(String token) {
        return Jwts.parser()
                .setSigningKey(secret.getBytes())
                .requireIssuer(issuer)           // FIX #7: Validate issuer
                .requireAudience(audience)       // FIX #7: Validate audience
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // FIX #7: Extract role from token with validation
    public String extractRole(String token) {
        return (String) Jwts.parser()
                .setSigningKey(secret.getBytes())
                .requireIssuer(issuer)
                .requireAudience(audience)
                .parseClaimsJws(token)
                .getBody()
                .get("role");
    }
}
