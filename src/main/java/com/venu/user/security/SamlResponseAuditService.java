package com.venu.user.security;

import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Stores an audit record only after Spring Security has validated the SAML response.
 * Raw SAML assertions and their sensitive attributes are deliberately not persisted.
 */
@Service
public class SamlResponseAuditService {
  private final JdbcTemplate jdbc;

  public SamlResponseAuditService(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  @PostConstruct
  public void initializeSchema() {
    jdbc.execute("CREATE TABLE IF NOT EXISTS app_saml_response_audit (" +
        "id VARCHAR(36) PRIMARY KEY, " +
        "event_type VARCHAR(32) NOT NULL, " +
        "issuer VARCHAR(512), " +
        "principal_name VARCHAR(512), " +
        "session_id VARCHAR(255), " +
        "app_id VARCHAR(128), " +
        "saml_session_index VARCHAR(512), " +
        "received_at TIMESTAMP WITH TIME ZONE NOT NULL)");
  }

  public void recordValidatedLogin(String issuer, String principalName,
      String sessionId, String appId, String samlSessionIndex) {
    jdbc.update("INSERT INTO app_saml_response_audit " +
            "(id, event_type, issuer, principal_name, session_id, app_id, " +
            "saml_session_index, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        UUID.randomUUID().toString(), "LOGIN_SUCCESS", issuer, principalName,
        sessionId, appId, samlSessionIndex, Instant.now());
  }
}
