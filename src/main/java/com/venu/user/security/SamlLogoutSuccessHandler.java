package com.venu.user.security;

import com.venu.user.configuration.SamlConfig;
import com.venu.user.model.CallBackUrls;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class SamlLogoutSuccessHandler implements LogoutSuccessHandler {
  private static final Logger logger = LoggerFactory.getLogger(SamlLogoutSuccessHandler.class);

  private final SamlConfig samlConfig;
  private final SamlAppContextService appContext;

  public SamlLogoutSuccessHandler(SamlConfig samlConfig, SamlAppContextService appContext) {
    this.samlConfig = samlConfig;
    this.appContext = appContext;
  }

  @Override
  public void onLogoutSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    String state = request.getParameter("RelayState");
    String appId = appContext.consumeLogout(state).orElse(null);
    if (appId == null) {
      logger.warn("SAML logout callback missing or invalid one-time state");
      response.sendError(
          HttpServletResponse.SC_UNAUTHORIZED, "Unrecognized SAML logout transaction");
      return;
    }
    CallBackUrls urls = samlConfig.getAppUrls(appId);
    if (urls == null || urls.logoutUrl() == null || urls.logoutUrl().isBlank()) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Logout URL not configured");
      return;
    }
    logger.info("SAML logout completed for configured application {}", appId);
    response.sendRedirect(urls.logoutUrl());
  }
}
