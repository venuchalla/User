package com.venu.user.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Reject a persisted cookie session superseded by a later login. */
public class ActiveSessionEnforcementFilter extends OncePerRequestFilter {
  private final ActiveSessionService activeSessions;

  public ActiveSessionEnforcementFilter(ActiveSessionService activeSessions) {
    this.activeSessions = activeSessions;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws ServletException, IOException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    var session = request.getSession(false);
    if (auth != null && auth.isAuthenticated() && session != null
        && !"anonymousUser".equals(auth.getPrincipal())
        && !activeSessions.isActive(auth.getName(), session.getId())) {
      SecurityContextHolder.clearContext();
      session.invalidate();
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Session is no longer active");
      return;
    }
    chain.doFilter(request, response);
  }
}
