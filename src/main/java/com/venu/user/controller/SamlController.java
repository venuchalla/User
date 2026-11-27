package com.venu.user.controller;

import com.venu.user.configuration.SamlConfig;
import com.venu.user.security.SamlAppContextService;
import com.venu.user.security.SamlProfile;
import com.venu.user.security.SamlTicketStore;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/saml")
public class SamlController {
  private static final Logger logger = LoggerFactory.getLogger(SamlController.class);

  private final SamlTicketStore ticketStore;
  private final boolean enabled;
  private final String registrationId;
  private final SamlConfig samlConfig;
  private final SamlAppContextService appContext;

  public SamlController(
      SamlTicketStore ticketStore,
      @Value("${app.saml.enabled:false}") boolean enabled,
      @Value("${app.saml.registration-id:zitadel}") String registrationId,
      SamlConfig samlConfig,
      SamlAppContextService appContext) {
    this.ticketStore = ticketStore;
    this.enabled = enabled;
    this.registrationId = registrationId;
    this.samlConfig = samlConfig;
    this.appContext = appContext;
  }

  @GetMapping("/login")
  public ResponseEntity<String> login(
      @RequestParam(name = "appId", required = false) String appId, HttpServletRequest request) {

    if (!enabled) {
      logger.warn("SAML login requested while SAML is disabled");
      return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
          .body("SAML login is disabled. Configure IdP metadata and set app.saml.enabled=true.");
    }
    if (appId == null || appId.isBlank() || samlConfig.getAppUrls(appId) == null) {
      return ResponseEntity.badRequest().body("Unknown or missing application identifier");
    }
    URI authenticationUrl =
        UriComponentsBuilder.fromPath("/saml2/authenticate/{registrationId}")
            .queryParam("RelayState", appId)
            .buildAndExpand(registrationId)
            .toUri();
    appContext.startLogin(request, appId);
    logger.info("saml login posting url : {}", authenticationUrl);
    return ResponseEntity.status(HttpStatus.SEE_OTHER).location(authenticationUrl).build();
  }

  @GetMapping("/current-app")
  public ResponseEntity<?> currentApp(HttpServletRequest request) {
    return appContext
        .authenticatedApp(request)
        .<ResponseEntity<?>>map(id -> ResponseEntity.ok(java.util.Map.of("appId", id)))
        .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
  }

  @GetMapping("/profile-data")
  public ResponseEntity<SamlProfile> profile(@RequestParam String ticket) {
    return ticketStore
        .consume(ticket)
        .map(profile -> ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(profile))
        .orElseGet(() -> ResponseEntity.notFound().build());
  }
}
