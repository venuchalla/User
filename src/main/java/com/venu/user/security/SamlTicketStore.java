package com.venu.user.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/** One-time SAML profile tickets, shared across application instances. */
@Component
public class SamlTicketStore {
  private static final SecureRandom RANDOM = new SecureRandom();
  private final JdbcTemplate jdbc;
  private final ObjectMapper mapper;
  private final TransactionTemplate transaction;

  public SamlTicketStore(
      JdbcTemplate jdbc,
      ObjectMapper mapper,
      org.springframework.transaction.PlatformTransactionManager manager) {
    this.jdbc = jdbc;
    this.mapper = mapper;
    this.transaction = new TransactionTemplate(manager);
  }

  @PostConstruct
  public void initialize() {
    jdbc.execute(
        "CREATE TABLE IF NOT EXISTS app_saml_ticket ("
            + "ticket_hash VARCHAR(64) PRIMARY KEY, profile_json TEXT NOT NULL, "
            + "expires_at TIMESTAMP WITH TIME ZONE NOT NULL)");
  }

  public String issue(SamlProfile profile) {
    byte[] random = new byte[32];
    RANDOM.nextBytes(random);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    try {
      jdbc.update(
          "insert into app_saml_ticket(ticket_hash, profile_json, expires_at) values(?,?,?)",
          hash(token),
          mapper.writeValueAsString(profile),
          Instant.now().plusSeconds(120));
      return token;
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
      throw new IllegalStateException("Could not serialize SAML profile", e);
    }
  }

  public Optional<SamlProfile> consume(String ticket) {
    if (ticket == null || ticket.isBlank()) return Optional.empty();
    return transaction.execute(
        status -> {
          var rows =
              jdbc.query(
                  "select profile_json, expires_at from app_saml_ticket where ticket_hash = ? for update",
                  (rs, i) -> new TicketRow(rs.getString(1), rs.getTimestamp(2).toInstant()),
                  hash(ticket));
          if (rows.isEmpty()) return Optional.<SamlProfile>empty();
          jdbc.update("delete from app_saml_ticket where ticket_hash = ?", hash(ticket));
          TicketRow row = rows.get(0);
          if (!row.expiresAt().isAfter(Instant.now())) return Optional.<SamlProfile>empty();
          try {
            return Optional.of(mapper.readValue(row.json(), SamlProfile.class));
          } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Could not deserialize SAML profile", e);
          }
        });
  }

  private String hash(String token) {
    try {
      byte[] bytes =
          MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
      return java.util.HexFormat.of().formatHex(bytes);
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private record TicketRow(String json, Instant expiresAt) {}
}
