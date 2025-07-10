package org.springjson.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig - Main security configuration class for the application.
 * <p>
 * Configures:
 * - Authentication and authorization rules
 * - JWT filter setup
 * - Password encoding
 * - CSRF and session management
 * - Role-based access control
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationConfiguration authenticationConfiguration;

    // TODO: Uncomment and configure in application.properties
    // @Value("${jwt.secret}")
    // private String jwtSecret;

    /**
     * Configures the security filter chain with:
     * - Stateless JWT authentication
     * - Public and protected endpoints
     * - Role-based authorization
     * - Custom JWT filters
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Configure custom authentication filter
        CustomAuthentcationFilter customAuthFilter = new CustomAuthentcationFilter(
                authenticationManager(authenticationConfiguration)
        );
        customAuthFilter.setFilterProcessesUrl("/api/login");

        http
                // Disable CSRF for stateless JWT authentication
                .csrf(csrf -> csrf.disable())

                // Configure stateless session management
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                                // Public endpoints
                                .requestMatchers(
                                        "/api/signup/**",
                                        "/api/login/**",       // Login endpoint
                                        "/api/signin/**",       // Login endpoint
                                        "/api/tokenrefresh/**", // Token refresh
                                        "/error"              // Error handling

//                                "/api/alluser/**",
//                                "/api/datasubmit"
                                ).permitAll()

                                // Role-based authorization
//                        .requestMatchers(HttpMethod.GET, "/api/user/**").hasAuthority("ROLE_USER")
//                        .requestMatchers(HttpMethod.POST, "/api/saveuser/**","/api/addroletouser/**").hasAuthority("ROLE_ADMIN")
//                        .requestMatchers(HttpMethod.DELETE,"/api/delete/**").hasAuthority("ROLE_ADMIN")
//                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                                // All other requests require authentication
                                .anyRequest().authenticated()
                )

                // Add custom filters
                .addFilter(customAuthFilter)
                .addFilterBefore(new CustomAuthorizationFilter(),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
    //TODO:learn more about DaoAuthenticationProvider

    /**
     * Configures the authentication provider with:
     * - Custom user details service
     * - Password encoder
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(bCryptPasswordEncoder);
        return authProvider;
    }

    /**
     * Exposes the AuthenticationManager bean
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Configures password encoder bean
     * Note: Bean name changed to avoid conflict with existing bean
     */
    @Bean(name = "newBeanName")
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}