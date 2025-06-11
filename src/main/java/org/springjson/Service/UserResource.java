package org.springjson.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springjson.domain.Role;
import org.springjson.domain.User;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * UserResource - REST Controller for managing users, roles, and token operations.
 *
 * Provides endpoints for:
 * - User management (CRUD operations)
 * - Role management
 * - Assigning roles to users
 * - JWT token refresh functionality
 *
 * All endpoints are prefixed with "/api"
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserResource {
    private final UserService userService;

    /**
     * Retrieves all users from the system
     * @return ResponseEntity containing list of all users with 200 OK status
     */
    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    /**
     * Creates a new user in the system
     * @param user User object to be created (from request body)
     * @return ResponseEntity with created user and 201 Created status
     */
    @PostMapping("/saveuser")
    public ResponseEntity<User> saveUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/api/saveuser").toUriString());
        return ResponseEntity.created(uri).body(userService.saveuser(user));
    }

    /**
     * Creates a new role in the system
     * @param role Role object to be created (from request body)
     * @return ResponseEntity with created role and 201 Created status
     */
    @PostMapping("/SaveRole")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/api/SaveRole").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    /**
     * Assigns a role to an existing user
     * @param form DTO containing username and roleName (from request body)
     * @return ResponseEntity with 200 OK status on success
     */
    @PostMapping("/addroletouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    /**
     * Refreshes the access token using a valid refresh token
     * @param request HttpServletRequest containing Authorization header with refresh token
     * @param response HttpServletResponse where new tokens or errors will be written
     * @throws IOException if response writing fails
     * @throws RuntimeException if refresh token is missing or invalid
     */
    @GetMapping("/tokenrefresh")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Refresh token is missing");
        }

        try {
            String refreshToken = authorizationHeader.substring("Bearer ".length());
            Algorithm algorithm = Algorithm.HMAC256("jwtSecret".getBytes());

            // Verify and decode the refresh token
            DecodedJWT decodedJWT = JWT.require(algorithm).build().verify(refreshToken);
            String username = decodedJWT.getSubject();

            // Get user details from database
            User user = userService.getUser(username);

            // Generate new access token
            String accessToken = generateNewAccessToken(request, user, algorithm, response);
            if (accessToken == null) return; // Error already handled

            // Prepare and send token response
            sendTokenResponse(response, accessToken, refreshToken);

        } catch (Exception e) {
            handleTokenRefreshError(response, e);
        }
    }

    /**
     * Generates a new access token for the user
     * @param request HttpServletRequest for issuer URL
     * @param user User details
     * @param algorithm JWT signing algorithm
     * @param response HttpServletResponse for error handling
     * @return New access token or null if generation fails
     */
    private String generateNewAccessToken(HttpServletRequest request,
                                          User user,
                                          Algorithm algorithm,
                                          HttpServletResponse response) {
        try {
            return JWT.create()
                    .withSubject(user.getUsername())
                    .withClaim("roles", user.getRoles().stream()
                            .map(Role::getName)
                            .collect(Collectors.toList()))
                    .withExpiresAt(new Date(System.currentTimeMillis() + 1 * 60 * 1000)) // 1 minute expiration
                    .withIssuer(request.getRequestURL().toString())
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            log.error("JWT token creation failed", exception);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return null;
        }
    }

    /**
     * Sends the token response as JSON
     * @param response HttpServletResponse to write to
     * @param accessToken New access token
     * @param refreshToken Existing refresh token
     * @throws IOException if response writing fails
     */
    private void sendTokenResponse(HttpServletResponse response,
                                   String accessToken,
                                   String refreshToken) throws IOException {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

    /**
     * Handles errors during token refresh
     * @param response HttpServletResponse for error response
     * @param exception Exception that occurred
     * @throws IOException if response writing fails
     */
    private void handleTokenRefreshError(HttpServletResponse response,
                                         Exception exception) throws IOException {
        log.error("Error during token refresh: {}", exception.getMessage());
        response.setHeader("error", exception.getMessage());
        response.setStatus(FORBIDDEN.value());

        Map<String, String> error = new HashMap<>();
        error.put("error_message", exception.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}

/**
 * RoleToUserForm - Data Transfer Object for assigning roles to users
 */
@Data
class RoleToUserForm {
    /** Username to assign the role to */
    private String username;

    /** Name of the role to be assigned */
    private String roleName;
}