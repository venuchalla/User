package com.venu.user.security;

import com.venu.user.configuration.SamlConfig;
import com.venu.user.model.CallBackUrls;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class SamlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
  private static final Logger logger =
      LoggerFactory.getLogger(SamlAuthenticationSuccessHandler.class);

  private final SamlTicketStore ticketStore;
  private final String idpEntityId;
  // private final String frontendProfileUrl;
  private final SamlConfig samlConfig;

  public SamlAuthenticationSuccessHandler(
      SamlTicketStore ticketStore,
      @Value("${app.saml.idp-entity-id}") String idpEntityId,
      SamlConfig samlConfig) {
    this.ticketStore = ticketStore;
    this.idpEntityId = idpEntityId;
    this.samlConfig = samlConfig;
  }

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    String relayState = request.getParameter("RelayState");
    logger.info(
        "saml login success login and passed to  success handler relay state : {}", relayState);
    CallBackUrls callBackUrls = samlConfig.getAppUrls(relayState);
    if (!(authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal)) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid SAML authentication result");
      return;
    }

    if (idpEntityId.isBlank()) {
      response.sendError(
          HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "SAML identity provider is not configured");
      return;
    }
    Map<String, Object> attributes = new LinkedHashMap<>();
    principal
        .getAttributes()
        .forEach(
            (name, values) -> {
              List<String> stringValues =
                  values.stream().filter(Objects::nonNull).map(String::valueOf).toList();
              if (stringValues.size() == 1) {
                attributes.put(name, stringValues.get(0));
              } else if (!stringValues.isEmpty()) {
                attributes.put(name, stringValues);
              }
            });
    attributes.put("RelayState", relayState);
    request.getSession().setAttribute("RelayState", relayState);
    // attributes.put("errorUrl", callBackUrls.errorUrl());
    // attributes.put("successUrl",callBackUrls.successUrl());
    // attributes.put("logoutUrl",callBackUrls.logoutUrl());
    String sessionIndex = principal.getSessionIndexes().stream().findFirst().orElse(null);
    String ticket =
        ticketStore.issue(
            new SamlProfile(
                idpEntityId, principal.getName(), null, sessionIndex, Map.copyOf(attributes)));

    String redirectUrl =
        UriComponentsBuilder.fromUriString(callBackUrls.successUrl())
            .queryParam("ticket", ticket)
            .build()
            .encode()
            .toUriString();
    logger.info("LOGIN SESSION={}", request.getSession().getId());
    logger.info(
        "SAML authentication succeeded; redirecting to the profile page with a one-time ticket,{}",
        redirectUrl);
    getRedirectStrategy().sendRedirect(request, response, redirectUrl);
  }
}
