package com.explorer.spring.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.explorer.spring.security.jwt.AuthEntryPointJwt;
import com.explorer.spring.security.jwt.AuthTokenFilter;
import com.explorer.spring.security.services.UserDetailsServiceImpl;

/**
 * Security configuration class to set up Spring Security.
 */
@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {

  @Autowired
  UserDetailsServiceImpl userDetailsService; 

  @Autowired
  private AuthEntryPointJwt unauthorizedHandler;

  /**
   * Creates a bean for the authentication JWT token filter.
   *
   * @return AuthTokenFilter instance
   */
  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter(); // Returns a new instance of AuthTokenFilter
  }

  /**
   * Creates a bean for the DAO authentication provider.
   *
   * @return DaoAuthenticationProvider instance
   */
  @Bean
  public DaoAuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(); // Create a new authentication provider

    authProvider.setUserDetailsService(userDetailsService);
    authProvider.setPasswordEncoder(passwordEncoder());

    return authProvider; // Return the configured authentication provider
  }

  /**
   * Creates a bean for the authentication manager.
   *
   * @param authConfig Authentication configuration
   * @return AuthenticationManager instance
   * @throws Exception if there is an error getting the authentication manager
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager(); // Returns the authentication manager from the configuration
  }

  /**
   * Creates a bean for the password encoder.
   *
   * @return PasswordEncoder instance
   */
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // Returns a new instance of BCryptPasswordEncoder
  }

  /**
   * Configures the security filter chain for HTTP requests.
   *
   * @param http HttpSecurity configuration
   * @return SecurityFilterChain instance
   * @throws Exception if there is an error configuring the security filter chain
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.csrf(AbstractHttpConfigurer::disable) // Disable CSRF protection
            .exceptionHandling(exception ->
                    exception.authenticationEntryPoint(unauthorizedHandler))
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/auth/**").permitAll()
                    .requestMatchers("/api/test/**").permitAll()
                    .anyRequest().authenticated());

    http.authenticationProvider(authenticationProvider()); 
    http.addFilterBefore(authenticationJwtTokenFilter(),
            UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
  
  //inmemory authentication for simple use case
//  @Bean
//  public InMemoryUserDetailsManager userDetailsService() {
//	  String encryptedAdminpassword = this.passwordEncoder().encode("adminPassword");
//	  String encryptedUserpassword = this.passwordEncoder().encode("userPassword");
//	  UserDetails admin = User.withUsername("adminName").password(encryptedAdminpassword).authorities("ROLE_ADMIN").build();
//	  UserDetails user = User.withUsername("userName").password(encryptedUserpassword).authorities("ROLE_USER").build();
//	  return new InMemoryUserDetailsManager(admin,user);
//  }
}
