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

  public SamlLogoutSuccessHandler(SamlConfig samlConfig) {
    this.samlConfig = samlConfig;
  }

  @Override
  public void onLogoutSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    String relayState = String.valueOf(request.getParameter("RelayState"));
    logger.info("saml logout success {}", relayState);
    CallBackUrls callBackUrls = samlConfig.getAppUrls(relayState);
    logger.info(
        "SAML logout succeeded; redirecting browser to the frontend completion route {}",
        callBackUrls.logoutUrl());
    response.sendRedirect(callBackUrls.logoutUrl());
  }
}
