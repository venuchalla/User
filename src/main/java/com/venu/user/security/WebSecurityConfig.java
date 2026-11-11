package com.venu.user.security;

import com.venu.user.model.enums.UserRole;
import com.venu.user.service.CreditionaldetailsServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.core.annotation.Order;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.beans.factory.annotation.Value;

import java.util.List;


//need to be fixed
//        securedEnabled = true,
//         jsr250Enabled = true,
@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(
//        prePostEnabled = true)
public class WebSecurityConfig {//extends WebSecurityConfigurerAdapter {
    Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
    @Autowired
    CreditionaldetailsServiceImpl creditionaldetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
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
            AuthEntryPointJwt unauthorizedHandler)
            throws Exception {

        http
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.sameOrigin())
                )

                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(unauthorizedHandler)
                )

                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/signup")
                        .hasAnyAuthority("MODERATOR", "ADMIN")
                        .requestMatchers(
                                        "/public/**",
                                        "/saml/**",
                                        "/saml2/metadata/**",
                                        "/h2-console",
                                        "/h2-console/**",
                                        "/auth/**",
                                        "/actuator/**"
                                ).permitAll()
                        .requestMatchers("/removeallusers")
                        .hasAuthority("ADMIN")

                        .requestMatchers("/pagination/**")
                        .hasAnyAuthority("ADMIN", "MODERATOR")

                        .requestMatchers("/userdetails/**")
                        .hasAnyAuthority("USER", "ADMIN", "MODERATOR")
                        .requestMatchers("/auth/**")
                        .permitAll()

                        .anyRequest().authenticated()

                )

                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origins}") List<String> allowedOrigins,
            @Value("${app.saml.frontend-origin:https://localhost:4200}") String frontendOrigin,
            @Value("${app.saml.idp-origin}") String identityProviderOrigin) {
        CorsConfiguration apiConfiguration = new CorsConfiguration();
        apiConfiguration.setAllowedOrigins(allowedOrigins);
        apiConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        apiConfiguration.setAllowedHeaders(
                List.of("Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"));
        apiConfiguration.setAllowCredentials(true);

        CorsConfiguration samlConfiguration = new CorsConfiguration(apiConfiguration);
        samlConfiguration.setAllowedOrigins(List.of(frontendOrigin, identityProviderOrigin));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/saml/**", samlConfiguration);
        source.registerCorsConfiguration("/**", apiConfiguration);
        return source;
    }

}
