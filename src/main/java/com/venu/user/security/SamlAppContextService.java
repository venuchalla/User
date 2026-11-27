package com.venu.user.security;

import com.venu.user.configuration.SamlConfig;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Validated frontend app binding for SAML login and single logout. */
@Service
public class SamlAppContextService {
  public static final String LOGIN_APP_ID = "SAML_LOGIN_APP_ID";
  public static final String AUTHENTICATED_APP_ID = "SAML_AUTHENTICATED_APP_ID";
  private static final SecureRandom RANDOM = new SecureRandom();
  private final JdbcTemplate jdbc;
  private final SamlConfig config;
  private final TransactionTemplate transactions;

  public SamlAppContextService(
      JdbcTemplate jdbc,
      SamlConfig config,
      org.springframework.transaction.PlatformTransactionManager transactionManager) {
    this.jdbc = jdbc;
    this.config = config;
    this.transactions = new TransactionTemplate(transactionManager);
  }

  @PostConstruct
  public void initialize() {
    jdbc.execute(
        "CREATE TABLE IF NOT EXISTS app_saml_logout_state ("
            + "state_id VARCHAR(100) PRIMARY KEY, app_id VARCHAR(128) NOT NULL, "
            + "session_id VARCHAR(255) NOT NULL, expires_at TIMESTAMP WITH TIME ZONE NOT NULL)");
  }

  public boolean isConfigured(String appId) {
    return appId != null && !appId.isBlank() && config.getAppUrls(appId) != null;
  }

  public void startLogin(HttpServletRequest request, String appId) {
    if (!isConfigured(appId)) throw new IllegalArgumentException("Unknown SAML application");
    HttpSession session = request.getSession(true);
    session.setAttribute(LOGIN_APP_ID, appId);
    session.setAttribute("RelayState", appId);
  }

  public Optional<String> pendingLoginApp(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) return Optional.empty();
    Object appId = session.getAttribute(LOGIN_APP_ID);
    return appId instanceof String id && isConfigured(id) ? Optional.of(id) : Optional.empty();
  }

  public void finishLogin(HttpServletRequest request, String appId) {
    if (!pendingLoginApp(request).filter(appId::equals).isPresent())
      throw new IllegalStateException("SAML login application mismatch");
    HttpSession session = request.getSession(false);
    session.setAttribute(AUTHENTICATED_APP_ID, appId);
    session.removeAttribute(LOGIN_APP_ID);
    session.removeAttribute("RelayState");
  }

  public Optional<String> authenticatedApp(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    if (session == null) return Optional.empty();
    Object appId = session.getAttribute(AUTHENTICATED_APP_ID);
    return appId instanceof String id && isConfigured(id) ? Optional.of(id) : Optional.empty();
  }

  /** Persist before Spring Security invalidates the browser session. */
  public String prepareLogout(HttpServletRequest request) {
    String appId =
        authenticatedApp(request)
            .orElseThrow(
                () -> new IllegalStateException("No SAML frontend application in session"));
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    String state = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    jdbc.update(
        "INSERT INTO app_saml_logout_state(state_id, app_id, session_id, expires_at) "
            + "VALUES (?, ?, ?, ?)",
        state,
        appId,
        request.getSession(false).getId(),
        Instant.now().plusSeconds(300));
    return state;
  }

  /** Single-use state survives logout/session invalidation and backend restarts. */
  public Optional<String> consumeLogout(String state) {
    if (state == null || state.isBlank()) return Optional.empty();
    return transactions.execute(
        status -> {
          var rows =
              jdbc.query(
                  "SELECT app_id, expires_at FROM app_saml_logout_state WHERE state_id = ? FOR UPDATE",
                  (rs, row) -> new LogoutState(rs.getString(1), rs.getTimestamp(2).toInstant()),
                  state);
          if (rows.isEmpty()) return Optional.<String>empty();
          jdbc.update("DELETE FROM app_saml_logout_state WHERE state_id = ?", state);
          LogoutState entry = rows.get(0);
          return entry.expiresAt().isAfter(Instant.now()) && isConfigured(entry.appId())
              ? Optional.of(entry.appId())
              : Optional.<String>empty();
        });
  }

  private record LogoutState(String appId, Instant expiresAt) {}
}
