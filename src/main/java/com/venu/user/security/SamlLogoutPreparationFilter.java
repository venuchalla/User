package com.venu.user.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/** Captures app context before Spring Security's SAML logout invalidates the session. */
public final class SamlLogoutPreparationFilter extends OncePerRequestFilter {
  public static final String LOGOUT_STATE_ATTRIBUTE =
      SamlLogoutPreparationFilter.class.getName() + ".logoutState";
  private final SamlAppContextService appContext;

  public SamlLogoutPreparationFilter(SamlAppContextService appContext) {
    this.appContext = appContext;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !"/saml/logout".equals(request.getServletPath())
        || !"POST".equalsIgnoreCase(request.getMethod());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (appContext.authenticatedApp(request).isEmpty()) {
      response.sendError(
          HttpServletResponse.SC_UNAUTHORIZED, "No authenticated SAML application in session");
      return;
    }
    String state = appContext.prepareLogout(request);
    request.setAttribute(LOGOUT_STATE_ATTRIBUTE, state);
    chain.doFilter(request, response);
  }
}
