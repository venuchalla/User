package com.venu.user.controller;

import com.venu.user.security.ActiveSessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/session")
public class SessionController {
  @Autowired private ActiveSessionService activeSessions;

  @PostMapping("/logout")
  public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    HttpSession session = request.getSession(false);
    if (session != null
        && auth != null
        && auth.isAuthenticated()
        && !"anonymousUser".equals(auth.getPrincipal())) {
      activeSessions.revoke(auth.getName(), session.getId());
    }
    new SecurityContextLogoutHandler().logout(request, response, auth);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/csrf")
  public ResponseEntity<?> csrf(CsrfToken csrfToken) {
    return ResponseEntity.ok(
        Map.of("headerName", csrfToken.getHeaderName(), "token", csrfToken.getToken()));
  }

  @GetMapping
  public ResponseEntity<?> current(HttpServletRequest request) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    HttpSession session = request.getSession(false);
    if (auth == null
        || !auth.isAuthenticated()
        || "anonymousUser".equals(auth.getPrincipal())
        || session == null) {
      return ResponseEntity.status(401).body(Map.of("authenticated", false));
    }
    return ResponseEntity.ok(
        Map.of(
            "authenticated", true,
            "username", auth.getName(),
            "expiresInSeconds", session.getMaxInactiveInterval()));
  }

  @PostMapping("/extend")
  public ResponseEntity<?> extend(HttpServletRequest request) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    HttpSession session = request.getSession(false);
    if (session == null
        || auth == null
        || !auth.isAuthenticated()
        || "anonymousUser".equals(auth.getPrincipal())) {
      return ResponseEntity.status(401).body(Map.of("authenticated", false));
    }
    session.setAttribute("lastAuthenticatedActivity", Instant.now().toString());
    return ResponseEntity.ok(
        Map.of("authenticated", true, "expiresInSeconds", session.getMaxInactiveInterval()));
  }
}
