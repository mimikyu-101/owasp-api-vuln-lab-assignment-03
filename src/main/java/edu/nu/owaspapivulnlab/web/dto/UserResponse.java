package edu.nu.owaspapivulnlab.web.dto;

import edu.nu.owaspapivulnlab.model.AppUser;

/**
 * FIX #4: DTO used to prevent Excessive Data Exposure.
 * Exposes only non-sensitive fields to API clients.
 * Intentionally omits password, role, isAdmin and internal flags.
 */
public class UserResponse {
    private Long id;
    private String username;
    private String email;
    
    public UserResponse() {}
    
    public UserResponse(Long id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }
    
    public static UserResponse from(AppUser u) {
        return new UserResponse(u.getId(), u.getUsername(), u.getEmail());
    }
    
    // Getters
    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getEmail() { return email; }
    
    // Setters
    public void setId(Long id) { this.id = id; }
    public void setUsername(String username) { this.username = username; }
    public void setEmail(String email) { this.email = email; }
}
