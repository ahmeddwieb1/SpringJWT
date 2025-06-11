package org.springjson.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * CustomAuthorizationFilter - JWT Authorization Filter that validates access tokens
 * and sets up Spring Security authentication context.
 *
 * This filter:
 * 1. Skips authorization for login and token refresh endpoints
 * 2. Validates JWT tokens from Authorization header
 * 3. Extracts user roles from the token
 * 4. Sets up Spring Security context for authenticated users
 * 5. Handles authorization errors with proper JSON responses
 *
 * Extends OncePerRequestFilter to ensure single execution per request
 */
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    /**
     * Processes each HTTP request to check JWT authorization
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param filterChain FilterChain to continue processing
     * @throws ServletException if servlet error occurs
     * @throws IOException if I/O error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Skip authorization for login and token refresh endpoints
        if (isPublicEndpoint(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Process Authorization header
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if (isBearerTokenPresent(authorizationHeader)) {
            try {
                authenticateUserAndProceed(request, response, filterChain, authorizationHeader);
            } catch (Exception e) {
                handleAuthorizationError(response, e);
            }
        } else {
            // No authorization header - continue filter chain (other filters may handle auth)
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Checks if request is for a public endpoint that doesn't require authorization
     * @param request HttpServletRequest to check
     * @return true if public endpoint, false otherwise
     */
    private boolean isPublicEndpoint(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.equals("/api/login") || path.equals("/api/tokenrefresh");
    }

    /**
     * Checks if Authorization header contains a Bearer token
     * @param authorizationHeader Authorization header value
     * @return true if valid Bearer token present, false otherwise
     */
    private boolean isBearerTokenPresent(String authorizationHeader) {
        return authorizationHeader != null && authorizationHeader.startsWith("Bearer ");
    }

    /**
     * Authenticates user from JWT token and continues filter chain
     * @param request HttpServletRequest
     * @param response HttpServletResponse
     * @param filterChain FilterChain
     * @param authorizationHeader Authorization header containing JWT
     * @throws Exception if token validation or authentication fails
     */
    private void authenticateUserAndProceed(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain filterChain,
                                            String authorizationHeader) throws Exception {
        String token = authorizationHeader.substring("Bearer ".length());

        // TODO: Replace with dynamic secret from configuration
        Algorithm algorithm = Algorithm.HMAC256("jwtSecret".getBytes());

        DecodedJWT decodedJWT = JWT.require(algorithm).build().verify(token);
        String username = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

        // Convert roles to Spring Security authorities
        Collection<SimpleGrantedAuthority> authorities = extractAuthorities(roles);

        // Set up Spring Security context
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        // Continue filter chain with authenticated user
        filterChain.doFilter(request, response);
    }

    /**
     * Converts JWT role claims to Spring Security authorities
     * @param roles Array of role names from JWT
     * @return Collection of granted authorities
     */
    private Collection<SimpleGrantedAuthority> extractAuthorities(String[] roles) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        stream(roles).forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role));
        });
        return authorities;
    }

    /**
     * Handles authorization errors by sending JSON error response
     * @param response HttpServletResponse
     * @param exception Exception that occurred
     * @throws IOException if response writing fails
     */
    private void handleAuthorizationError(HttpServletResponse response,
                                          Exception exception) throws IOException {
        log.error("Authorization error: {}", exception.getMessage());
        response.setHeader("error", exception.getMessage());
        response.setStatus(FORBIDDEN.value());

        Map<String, String> error = new HashMap<>();
        error.put("error_message", exception.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}