
# OWASP API Vulnerable Lab – Security Fixes

This branch contains the **secure version** of the OWASP API Vulnerable Lab, with all major vulnerabilities identified and fixed according to secure coding best practices and the OWASP API Security Top 10 (2023).


## Quick Start

```bash
# Java 17 + Maven required
mvn spring-boot:run
# H2 Console: http://localhost:8080/h2-console (JDBC URL: jdbc:h2:mem:apilab)
```


## Seed Users

- `alice / alice123` (USER)
- `bob / bob123` (ADMIN)

Login to get a JWT:
```bash
curl -s -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice123"}'
# => {"token":"<JWT>"}
```

Use the token:
```bash
export T="<JWT>"
curl -H "Authorization: Bearer $T" http://localhost:8080/api/accounts/mine
```


## Security Fixes Implemented

This branch addresses the following vulnerabilities:

1. **Password Security:**
	- Plaintext password storage and comparison replaced with BCrypt hashing.
	- Signup/authentication flow updated; seeded users migrated to hashed passwords.
2. **Access Control:**
	- SecurityFilterChain strengthened; `permitAll` removed from `/api/**`.
	- Authentication required for sensitive endpoints; role-based access enforced.
3. **Resource Ownership Enforcement:**
	- Controller methods validate that users can only access their own resources.
	- Authenticated user identity mapped to userId; ownership checked before processing.
4. **Data Exposure Control:**
	- Data Transfer Objects (DTOs) restrict returned data; sensitive fields (password, role, isAdmin) never exposed.
5. **Rate Limiting:**
	- Rate limiting applied to critical endpoints using Bucket4j/Resilience4j to prevent abuse and brute-force attacks.
6. **Mass Assignment Prevention:**
	- Explicit request DTOs exclude sensitive fields; server-side validation enforced.
7. **JWT Hardening:**
	- Strong secret key loaded from environment variables.
	- Short token lifetime (TTL); issuer and audience claims included and validated.
	- Strict signature and expiry validation.
8. **Error Handling & Logging:**
	- Error detail reduced in production; custom exception mapping implemented.
	- Secure server-side logging for error tracking.
9. **Input Validation:**
	- All user inputs validated; negative or excessively large numeric values rejected.
	- Data ranges and formats enforced.


## How to  Review

- All fixes are committed separately with descriptive messages and inline code comments.
- See the Pull Request for a full diff and explanation of each fix.
- For details on vulnerabilities and solutions, refer to the PDF report in the submission package.

---
**This branch is the secure, production-ready version. For the original vulnerable code, see the `vulnerable` branch.**
