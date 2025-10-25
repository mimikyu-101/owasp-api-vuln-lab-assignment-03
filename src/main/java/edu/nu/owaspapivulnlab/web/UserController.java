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

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // FIX #4: Return only safe fields using UserResponse DTO to prevent data exposure
    @GetMapping("/{id}")
    public UserResponse get(@PathVariable Long id) {
        AppUser u = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        return UserResponse.from(u); // FIX #4: Excludes password, role, isAdmin fields
    }

    // VULNERABILITY(API6: Mass Assignment) - binds role/isAdmin from client
    @PostMapping
    public AppUser create(@Valid @RequestBody AppUser body) {
        return users.save(body);
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
