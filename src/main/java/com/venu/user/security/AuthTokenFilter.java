package com.venu.user.security;

import com.venu.user.service.CreditionaldetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

public class AuthTokenFilter extends OncePerRequestFilter {
  @Autowired private JwtUtils jwtUtils;

  @Autowired private CreditionaldetailsServiceImpl userDetailsService;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if (isSamlRequest(request)) {
      if (isSamlLogoutRequest(request)) {
        logSamlLogoutRequest(request, response, filterChain);
      } else {
        filterChain.doFilter(request, response);
      }
      return;
    }

    try {
      logger.info("====method {} , url {}", request.getMethod(), request.getServletPath());
      String jwt = parseJwt(request);
      if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
        String username = jwtUtils.getUserNameFromJwtToken(jwt);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        logger.info("username:{} Role:{}", userDetails.getUsername(), userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception e) {
      logger.error("Cannot set user authentication: {}", e);
    }

    filterChain.doFilter(request, response);
  }

  private boolean isSamlRequest(HttpServletRequest request) {
    String path = request.getServletPath();
    return path.startsWith("/saml/")
        || path.startsWith("/saml2/")
        || path.startsWith("/login/")
        || path.startsWith("/logout/saml2/")
        || path.equals("/error")
        || path.equals("/favicon.ico");
  }

  private boolean isSamlLogoutRequest(HttpServletRequest request) {
    String path = request.getServletPath();
    return path.equals("/saml/logout")
        || path.equals("/saml/slo")
        || path.equals("/logout/saml2/slo");
  }

  private void logSamlLogoutRequest(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    boolean hasSamlResponse = request.getParameter("SAMLResponse") != null;
    boolean hasSamlRequest = request.getParameter("SAMLRequest") != null;
    boolean hasRelayState = request.getParameter("RelayState") != null;
    boolean hasSession = request.getSession(false) != null;
    boolean authenticationPresent = SecurityContextHolder.getContext().getAuthentication() != null;

    logger.info(
        "SAML logout endpoint request: method={}, path={}, SAMLResponse={}, "
            + "SAMLRequest={}, RelayState={}, sessionPresent={}, authenticationPresent={}",
        request.getMethod(),
        request.getServletPath(),
        hasSamlResponse,
        hasSamlRequest,
        hasRelayState,
        hasSession,
        authenticationPresent);
    try {
      filterChain.doFilter(request, response);
      logger.info(
          "SAML logout endpoint completed: method={}, path={}, status={}",
          request.getMethod(),
          request.getServletPath(),
          response.getStatus());
    } catch (ServletException | IOException exception) {
      logger.warn(
          "SAML logout endpoint failed: path={}, errorType={}",
          request.getServletPath(),
          exception.getClass().getSimpleName());
      throw exception;
    }
  }

  private String parseJwt(HttpServletRequest request) {
    String headerAuth = request.getHeader("Authorization");

    if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
      return headerAuth.substring(7, headerAuth.length());
    }

    return null;
  }
}
