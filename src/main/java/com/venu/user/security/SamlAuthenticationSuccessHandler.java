package com.venu.user.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
  private final String frontendProfileUrl;

  public SamlAuthenticationSuccessHandler(
      SamlTicketStore ticketStore,
      @Value("${app.saml.idp-entity-id}") String idpEntityId,
      @Value("${app.saml.frontend-profile-url}") String frontendProfileUrl) {
    this.ticketStore = ticketStore;
    this.idpEntityId = idpEntityId;
    this.frontendProfileUrl = frontendProfileUrl;
  }

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
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
                  values.stream().filter(value -> value != null).map(String::valueOf).toList();
              if (stringValues.size() == 1) {
                attributes.put(name, stringValues.get(0));
              } else if (!stringValues.isEmpty()) {
                attributes.put(name, stringValues);
              }
            });

    String sessionIndex = principal.getSessionIndexes().stream().findFirst().orElse(null);
    String ticket =
        ticketStore.issue(
            new SamlProfile(
                idpEntityId, principal.getName(), null, sessionIndex, Map.copyOf(attributes)));
    String redirectUrl =
        UriComponentsBuilder.fromUriString(frontendProfileUrl)
            .queryParam("ticket", ticket)
            .build()
            .encode()
            .toUriString();
    getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    logger.info(
        "SAML authentication succeeded; redirecting to the profile page with a one-time ticket");
  }
}
