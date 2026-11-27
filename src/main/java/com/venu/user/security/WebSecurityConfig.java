package com.venu.user.security;

import com.venu.user.service.CreditionaldetailsServiceImpl;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
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
  public FilterRegistrationBean<AuthTokenFilter> disableJwtServletAutoRegistration(
      AuthTokenFilter filter) {
    FilterRegistrationBean<AuthTokenFilter> registration = new FilterRegistrationBean<>(filter);
    registration.setEnabled(false);
    return registration;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  // H2 is a development-only servlet. It needs its own chain so the console
  // frame and POST requests work without weakening the application API chain.
  @Bean
  @Order(0)
  @ConditionalOnProperty(name = "spring.h2.console.enabled", havingValue = "true")
  public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher(PathRequest.toH2Console())
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
        .csrf(AbstractHttpConfigurer::disable)
        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http,
      AuthTokenFilter jwtAuthenticationFilter,
      AuthEntryPointJwt unauthorizedHandler,
      ActiveSessionService activeSessions,
      @Value("${app.dev.api-docs-public:false}") boolean apiDocsPublic)
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
        .authorizeHttpRequests(
            auth -> {
              if (apiDocsPublic) {
                auth.requestMatchers(
                        "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs", "/v3/api-docs/**")
                    .permitAll();
              }
              auth.requestMatchers("/actuator/health", "/actuator/health/**").permitAll();
              auth.requestMatchers(
                      "/auth/signin",
                      "/auth/signup",
                      "/auth/session/csrf",
                      "/public/**",
                      "/error",
                      "/favicon.ico")
                  .permitAll()
                  .requestMatchers("/removeallusers")
                  .hasAuthority("ADMIN")
                  .requestMatchers("/pagination/**")
                  .hasAnyAuthority("ADMIN", "MODERATOR")
                  .anyRequest()
                  .authenticated();
            })
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(
            new ActiveSessionEnforcementFilter(activeSessions), SecurityContextHolderFilter.class);

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
      @Value("${app.saml.idp-origin}") String identityProviderOrigin) {
    CorsConfiguration apiConfiguration = new CorsConfiguration();
    apiConfiguration.setAllowedOrigins(allowedOrigins);
    apiConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    apiConfiguration.setAllowedHeaders(
        List.of("Authorization", "Content-Type", "Accept", "X-XSRF-TOKEN", "X-Requested-With"));
    apiConfiguration.setAllowCredentials(true);

    // SAML HTTP-POST binding is a browser form POST from the identity provider.
    // Allow the configured IdP origin ONLY on the SAML assertion consumer endpoint.
    CorsConfiguration assertionConsumerConfiguration = new CorsConfiguration(apiConfiguration);
    java.util.ArrayList<String> assertionOrigins = new java.util.ArrayList<>(allowedOrigins);
    if (identityProviderOrigin != null
        && !identityProviderOrigin.isBlank()
        && !assertionOrigins.contains(identityProviderOrigin)) {
      assertionOrigins.add(identityProviderOrigin);
    }
    assertionConsumerConfiguration.setAllowedOrigins(assertionOrigins);
    assertionConsumerConfiguration.setAllowedMethods(List.of("POST", "OPTIONS"));

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/login/saml2/sso/**", assertionConsumerConfiguration);
    // IdP-initiated SAML logout and LogoutResponse callbacks may be POSTed by ZITADEL.
    source.registerCorsConfiguration("/saml/slo", assertionConsumerConfiguration);
    source.registerCorsConfiguration("/logout/saml2/slo", assertionConsumerConfiguration);
    source.registerCorsConfiguration("/**", apiConfiguration);
    // A SAML HTTP-POST binding is a top-level browser form navigation, not a
    // cross-origin XMLHttpRequest. Do not apply API CORS origin checks to
    // non-preflight ACS/SLO callbacks; Spring Security validates SAML messages.
    // OPTIONS remains subject to CORS, so this does not enable cross-origin XHR.
    return request -> {
      String path = request.getServletPath();
      boolean samlCallback =
          path.startsWith("/login/saml2/sso/")
              || path.equals("/saml/slo")
              || path.equals("/logout/saml2/slo");
      if (samlCallback
          && ("GET".equalsIgnoreCase(request.getMethod())
              || "POST".equalsIgnoreCase(request.getMethod()))) {
        return null;
      }
      return source.getCorsConfiguration(request);
    };
  }
}
