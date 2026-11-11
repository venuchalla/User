package com.venu.user.security;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SamlTicketStore {
  private static final Logger logger = LoggerFactory.getLogger(SamlTicketStore.class);
  private static final long TICKET_LIFETIME_SECONDS = 120;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private final Map<String, Ticket> tickets = new ConcurrentHashMap<>();

  public String issue(SamlProfile profile) {
    byte[] random = new byte[32];
    SECURE_RANDOM.nextBytes(random);
    String ticket = Base64.getUrlEncoder().withoutPadding().encodeToString(random);

    Instant expiresAt = Instant.now().plusSeconds(TICKET_LIFETIME_SECONDS);
    tickets.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(Instant.now()));
    tickets.put(ticket, new Ticket(profile, expiresAt));
    logger.debug(
        "Issued a one-time SAML profile ticket; lifetime={} seconds", TICKET_LIFETIME_SECONDS);
    return ticket;
  }

  public Optional<SamlProfile> consume(String ticket) {
    Ticket storedTicket = tickets.remove(ticket);
    if (storedTicket == null || !storedTicket.expiresAt().isAfter(Instant.now())) {
      logger.debug("SAML profile ticket was missing, expired, or already used");
      return Optional.empty();
    }
    logger.debug("Consumed a one-time SAML profile ticket");
    return Optional.of(storedTicket.profile());
  }

  private record Ticket(SamlProfile profile, Instant expiresAt) {}
}
