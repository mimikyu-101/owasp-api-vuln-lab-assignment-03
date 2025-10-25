package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import edu.nu.owaspapivulnlab.web.dto.UserResponse;
import edu.nu.owaspapivulnlab.web.dto.CreateUserRequest;
import org.springframework.security.crypto.password.PasswordEncoder;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder;      // FIX #6: Inject password encoder

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;     // FIX #6: Store encoder
    }

    // FIX #4: Return only safe fields using UserResponse DTO to prevent data exposure
    @GetMapping("/{id}")
    public UserResponse get(@PathVariable Long id) {
        AppUser u = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return UserResponse.from(u); // FIX #4: Excludes password, role, isAdmin fields
    }

    // FIX #6: Prevent mass assignment by using whitelist DTO and setting role/isAdmin server-side
    @PostMapping
    public UserResponse create(@Valid @RequestBody CreateUserRequest request) {
        // FIX #6: Create user with only safe fields from DTO
        AppUser newUser = AppUser.builder()
            .username(request.getUsername())
            .password(passwordEncoder.encode(request.getPassword())) // FIX #6: Hash password
            .email(request.getEmail())
            .role("USER")        // FIX #6: Always set to USER (server-side default)
            .isAdmin(false)      // FIX #6: Always set to false (server-side default)
            .build();

        AppUser saved = users.save(newUser);

        // FIX #6: Return safe DTO (no password exposed)
        return UserResponse.from(saved);
    }

    // FIX #4: Return only safe fields using UserResponse DTO (excludes password, role, isAdmin)
    @GetMapping("/search")
    public List<UserResponse> search(@RequestParam String q) {
        return users.search(q).stream().map(UserResponse::from).collect(Collectors.toList());
    }

    // FIX #4: Prevent excessive data exposure by returning only safe user fields via DTO
    @GetMapping
    public List<UserResponse> list() {
        return users.findAll().stream().map(UserResponse::from).collect(Collectors.toList());
    }

    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
