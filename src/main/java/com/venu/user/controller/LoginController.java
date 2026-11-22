package com.venu.user.controller;

import com.venu.user.model.*;
import com.venu.user.model.enums.UserRole;
import com.venu.user.repository.CreditionalRepository;
import com.venu.user.repository.RoleRepository;
import com.venu.user.security.JwtUtils;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController

@RequestMapping("/auth")
public class LoginController {
  Logger logger = LoggerFactory.getLogger(LoginController.class);

  @Autowired AuthenticationManager authenticationManager;

  @Autowired CreditionalRepository creditionalRepository;

  @Autowired RoleRepository roleRepository;

  @Autowired PasswordEncoder encoder;

  @Autowired JwtUtils jwtUtils;

  private final HttpSessionSecurityContextRepository securityContextRepository =
      new HttpSessionSecurityContextRepository();

  @PostMapping("/signin")
  public ResponseEntity<JwtResponse> authenticateUser(
      @Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response) {

    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(), loginRequest.getPassword()));
    boolean isAuthenticated = authentication.isAuthenticated();
    logger.info("isAuthenticated :{} ", authentication.isAuthenticated());
    request.getSession(true);
    request.changeSessionId();
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authentication);
    SecurityContextHolder.setContext(context);
    securityContextRepository.saveContext(context, request, response);
    String jwt = jwtUtils.generateJwtToken(authentication);

    CreditionalDetailsImpl userDetails = (CreditionalDetailsImpl) authentication.getPrincipal();
    List<String> roles =
        userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());

    return ResponseEntity.ok(
        new JwtResponse(
            jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (creditionalRepository.existsByUsername(signUpRequest.username())) {
      AppResponse<Object> signupRequestAppResponse =
          new AppResponse<>("Error: Username is already taken!", null);

      return ResponseEntity.badRequest().body(signupRequestAppResponse);
    }

    if (creditionalRepository.existsByEmail(signUpRequest.email())) {
      AppResponse<SignupRequest> signupRequestAppResponse =
          new AppResponse<>("Error: Email is already in use!", null);
      return ResponseEntity.badRequest().body(signupRequestAppResponse);
    }

    // Create new user's account
    Creditional creditional =
        new Creditional(
            signUpRequest.username(),
            signUpRequest.email(),
            encoder.encode(signUpRequest.password()));

    // Never trust role selection on a public registration endpoint.
    Role userRole = roleRepository.findByName(UserRole.USER)
        .orElseThrow(() -> new IllegalStateException("Default USER role not found"));
    Set<Role> roles = Set.of(userRole);

    creditional.setRoles(roles);
    creditionalRepository.save(creditional);
    AppResponse<SignupRequest> signupRequestAppResponse =
        new AppResponse<>("User registered successfully!", null);
    return ResponseEntity.status(HttpStatus.OK).body(signupRequestAppResponse);
  }
}
