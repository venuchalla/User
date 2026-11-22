package com.venu.user.security;

import com.venu.user.service.CreditionaldetailsServiceImpl;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

// need to be fixed
//        securedEnabled = true,
//         jsr250Enabled = true,
@Configuration
@EnableWebSecurity
// @EnableGlobalMethodSecurity(
//        prePostEnabled = true)
public class WebSecurityConfig { // extends WebSecurityConfigurerAdapter {
  Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
  @Autowired CreditionaldetailsServiceImpl creditionaldetailsService;

  @Autowired private AuthEntryPointJwt unauthorizedHandler;

  @Bean
  public AuthTokenFilter authenticationJwtTokenFilter() {
    return new AuthTokenFilter();
  }

  @Bean
  public FilterRegistrationBean<AuthTokenFilter> disableJwtServletAutoRegistration(AuthTokenFilter filter) {
    FilterRegistrationBean<AuthTokenFilter> registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      AuthTokenFilter jwtAuthenticationFilter,
      AuthEntryPointJwt unauthorizedHandler,
      ActiveSessionService activeSessions)
      throws Exception {

    http.cors(Customizer.withDefaults())
        .csrf(AbstractHttpConfigurer::disable)
        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
        .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
        .sessionManagement(
            session ->
                session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation(fixation -> fixation.changeSessionId()))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/auth/signin", "/auth/signup", "/auth/session/csrf", "/public/**", "/error", "/favicon.ico").permitAll()
            .requestMatchers("/removeallusers").hasAuthority("ADMIN")
            .requestMatchers("/pagination/**").hasAnyAuthority("ADMIN", "MODERATOR")
            .anyRequest().authenticated())
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(new ActiveSessionEnforcementFilter(activeSessions), SecurityContextHolderFilter.class);

    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
      throws Exception {
    return configuration.getAuthenticationManager();
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource(
      @Value("${app.cors.allowed-origins}") List<String> allowedOrigins,
      @Value("${app.saml.frontend-origin:https://localhost:4200}") List<String> frontendOrigin,
      @Value("${app.saml.idp-origin}") String identityProviderOrigin) {
    CorsConfiguration apiConfiguration = new CorsConfiguration();
    //    apiConfiguration.setAllowedOrigins(List.of("*"));
    //    apiConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE",
    // "OPTIONS"));
    //    apiConfiguration.setAllowedHeaders(
    //        List.of("Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"));
    //    apiConfiguration.setAllowCredentials(true);
    apiConfiguration.setAllowedOrigins(allowedOrigins);
    apiConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    apiConfiguration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "X-XSRF-TOKEN", "X-Requested-With"));
    apiConfiguration.setAllowCredentials(true);

   // CorsConfiguration samlConfiguration = new CorsConfiguration(apiConfiguration);
   // frontendOrigin.add(identityProviderOrigin);
   // samlConfiguration.setAllowedOrigins(frontendOrigin);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    // source.registerCorsConfiguration("/saml/**", samlConfiguration);
    source.registerCorsConfiguration("/**", apiConfiguration);
    return source;
  }
}
