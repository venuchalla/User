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
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class SamlAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
  private static final Logger logger =
      LoggerFactory.getLogger(SamlAuthenticationSuccessHandler.class);

  private final SamlTicketStore ticketStore;
  private final ActiveSessionService activeSessions;
  private final String idpEntityId;
  // private final String frontendProfileUrl;
  private final SamlConfig samlConfig;
  private final HttpSessionSecurityContextRepository contextRepository =
      new HttpSessionSecurityContextRepository();

  public SamlAuthenticationSuccessHandler(
      SamlTicketStore ticketStore,
      ActiveSessionService activeSessions,
      @Value("${app.saml.idp-entity-id}") String idpEntityId,
      SamlConfig samlConfig) {
    this.ticketStore = ticketStore;
    this.activeSessions = activeSessions;
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
    HttpSession session = request.getSession(false);
    Object expectedAppId = session == null ? null : session.getAttribute("RelayState");
    if (!(expectedAppId instanceof String) || !expectedAppId.equals(relayState)) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unrecognized SAML transaction");
      return;
    }
    CallBackUrls callBackUrls = samlConfig.getAppUrls(relayState);
    if (callBackUrls == null) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown frontend application");
      return;
    }
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
    // attributes.put("errorUrl", callBackUrls.errorUrl());
    // attributes.put("successUrl",callBackUrls.successUrl());
    // attributes.put("logoutUrl",callBackUrls.logoutUrl());
    // Spring Security invokes the success handler after authentication; persist the
    // context explicitly so Spring Session JDBC restores it on the next request.
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authentication);
    SecurityContextHolder.setContext(context);
    contextRepository.saveContext(context, request, response);
    activeSessions.register(authentication.getName(), session.getId(), "SAML");
    session.removeAttribute("RelayState");
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
    logger.info("SAML application session established for principal={}", authentication.getName());
    logger.info("SAML authentication succeeded; redirecting to configured frontend");
    getRedirectStrategy().sendRedirect(request, response, redirectUrl);
  }
}
