package com.venu.user.controller;

import com.venu.user.security.SamlProfile;
import com.venu.user.security.SamlTicketStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.CacheControl;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/saml")
public class SamlController {
    private static final Logger logger = LoggerFactory.getLogger(SamlController.class);

    private final SamlTicketStore ticketStore;
    private final boolean enabled;
    private final String registrationId;

    public SamlController(
            SamlTicketStore ticketStore,
            @Value("${app.saml.enabled:false}") boolean enabled,
            @Value("${app.saml.registration-id:zitadel}") String registrationId) {
        this.ticketStore = ticketStore;
        this.enabled = enabled;
        this.registrationId = registrationId;
    }

    @GetMapping("/login")
    public ResponseEntity<String> login() {
        if (!enabled) {
            logger.warn("SAML login requested while SAML is disabled");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("SAML login is disabled. Configure IdP metadata and set app.saml.enabled=true.");
        }

        logger.debug("Starting SAML login for registration {}", registrationId);
        URI authenticationUrl = UriComponentsBuilder
                .fromPath("/saml2/authenticate/{registrationId}")
                .buildAndExpand(registrationId)
                .toUri();
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .location(authenticationUrl)
                .build();
    }

    @GetMapping("/profile-data")
    public ResponseEntity<SamlProfile> profile(@RequestParam String ticket) {
        return ticketStore.consume(ticket)
                .map(profile -> ResponseEntity.ok()
                        .cacheControl(CacheControl.noStore())
                        .body(profile))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
