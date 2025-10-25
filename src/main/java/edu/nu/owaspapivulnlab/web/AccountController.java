package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // FIX #3: Add ownership validation to prevent BOLA (Broken Object Level Authorization)
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        
        // FIX #3: Verify the account belongs to the authenticated user
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            // FIX #3: Return 403 Forbidden if user tries to access someone else's account
            Map<String, String> error = new HashMap<>();
            error.put("error", "forbidden");
            error.put("message", "You do not have permission to access this account");
            return ResponseEntity.status(403).body(error);
        }
        
        return ResponseEntity.ok(account.getBalance());
    }

    // FIX #3: Add ownership validation to prevent unauthorized transfers (BOLA)
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));

        // FIX #3: Check if the current user is the owner of the account
        AppUser currentUser = users.findByUsername(auth.getName()).orElseThrow(() -> new RuntimeException("User not found"));

        if (!a.getOwnerUserId().equals(currentUser.getId())) {
            // FIX #3: Return 403 Forbidden if the user does not own the account
            Map<String, String> error = new HashMap<>();
            error.put("error", "forbidden");
            error.put("message", "You cannot transfer from an account you do not own");
            return ResponseEntity.status(403).body(error);
        }

        // Perform the transfer
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }

    // Safe-ish helper to view my accounts (still leaks more than needed)
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
