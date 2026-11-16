package com.venu.user.controller;

import com.venu.user.model.*;
import com.venu.user.model.enums.UserRole;
import com.venu.user.repository.CreditionalRepository;
import com.venu.user.repository.RoleRepository;
import com.venu.user.security.JwtUtils;
import jakarta.validation.Valid;
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
@CrossOrigin(origins = "*")
@RequestMapping("/auth")
public class LoginController {
  Logger logger = LoggerFactory.getLogger(LoginController.class);

  @Autowired AuthenticationManager authenticationManager;

  @Autowired CreditionalRepository creditionalRepository;

  @Autowired RoleRepository roleRepository;

  @Autowired PasswordEncoder encoder;

  @Autowired JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<JwtResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(), loginRequest.getPassword()));
    boolean isAuthenticated = authentication.isAuthenticated();
    logger.info("isAuthenticated :{} ", authentication.isAuthenticated());
    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);

    CreditionalDetailsImpl userDetails = (CreditionalDetailsImpl) authentication.getPrincipal();
    List<String> roles =
        userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (creditionalRepository.existsByUsername(signUpRequest.username())) {
      AppResponse<SignupRequest> signupRequestAppResponse = new AppResponse<>("Error: Username is already taken!",signUpRequest);

      return ResponseEntity.badRequest()
          .body(signupRequestAppResponse);
    }

    if (creditionalRepository.existsByEmail(signUpRequest.email())) {
      AppResponse<SignupRequest> signupRequestAppResponse = new AppResponse<>("Error: Email is already in use!",signUpRequest);
      return ResponseEntity.badRequest()
          .body(signupRequestAppResponse);
    }

    // Create new user's account
    Creditional creditional =
        new Creditional(
            signUpRequest.username(),
            signUpRequest.email(),
            encoder.encode(signUpRequest.password()));

    Set<String> strRoles = signUpRequest.role();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole =
          roleRepository
              .findByName(UserRole.USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(
          role -> {
            switch (role) {
              case "admin":
                Role adminRole =
                    roleRepository
                        .findByName(UserRole.ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(adminRole);

                break;
              case "mod":
                Role modRole =
                    roleRepository
                        .findByName(UserRole.MODERATOR)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(modRole);

                break;
              default:
                Role userRole =
                    roleRepository
                        .findByName(UserRole.USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                roles.add(userRole);
            }
          });
    }

    creditional.setRoles(roles);
    creditionalRepository.save(creditional);
     AppResponse<SignupRequest> signupRequestAppResponse = new AppResponse<>("User registered successfully!",signUpRequest);
    return ResponseEntity.status(HttpStatus.OK).body(signupRequestAppResponse);
  }
}
