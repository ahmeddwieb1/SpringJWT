package org.springjson.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * CustomAuthenticationFilter - Extends Spring Security's UsernamePasswordAuthenticationFilter
 * to provide JWT-based authentication.
 *
 * This filter handles:
 * 1. Authentication attempts (username/password validation)
 * 2. Successful authentication (JWT token generation)
 * 3. Token response formatting (JSON response with access and refresh tokens)
 *
 * Note: Currently uses a static secret key (marked with TODO for improvement)
 */
@Slf4j
public class CustomAuthentcationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    /**
     * Constructs the authentication filter with required dependencies
     * @param authenticationManager Spring Security authentication manager
     */
    public CustomAuthentcationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Attempts to authenticate the user with credentials from the request
     * @param request HttpServletRequest containing username/password parameters
     * @param response HttpServletResponse
     * @return Authentication object if successful
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        // Extract credentials from request parameters
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Authentication attempt for username: {}", username);

        // Create authentication token
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password);

        // Delegate authentication to the manager
        return authenticationManager.authenticate(authToken);
    }

    /**
     * Handles successful authentication by generating and returning JWT tokens
     * @param request HttpServletRequest
     * @param response HttpServletResponse where tokens will be written
     * @param chain FilterChain
     * @param authentication Successful authentication object containing user details
     * @throws IOException if response writing fails
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authentication) throws IOException {
        User user = (User) authentication.getPrincipal();

        // TODO: Replace with dynamic secret from configuration
        Algorithm algorithm = Algorithm.HMAC256("jwtSecret".getBytes());

        // Generate access token
        String accessToken = generateAccessToken(request, user, algorithm, response);
        if (accessToken == null) return; // Error already handled

        // Generate refresh token
        String refreshToken = generateRefreshToken(request, user, algorithm);

        // Prepare token response
        sendTokenResponse(response, accessToken, refreshToken);
    }

    /**
     * Generates the access JWT token with user claims
     * @param request HttpServletRequest for issuer URL
     * @param user Authenticated user details
     * @param algorithm JWT signing algorithm
     * @param response HttpServletResponse for error handling
     * @return Generated access token or null if generation fails
     */
    private String generateAccessToken(HttpServletRequest request,
                                       User user,
                                       Algorithm algorithm,
                                       HttpServletResponse response) {
        try {
            return JWT.create()
                    .withSubject(user.getUsername())
                    .withClaim("roles", user.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
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
     * Generates the refresh JWT token
     * @param request HttpServletRequest for issuer URL
     * @param user Authenticated user details
     * @param algorithm JWT signing algorithm
     * @return Generated refresh token
     */
    private String generateRefreshToken(HttpServletRequest request,
                                        User user,
                                        Algorithm algorithm) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) // 30 minutes expiration
                .withIssuer(request.getRequestURI().toString())
                .sign(algorithm);
    }

    /**
     * Sends the token response as JSON
     * @param response HttpServletResponse to write to
     * @param accessToken JWT access token
     * @param refreshToken JWT refresh token
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
}