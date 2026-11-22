package com.venu.user.security;

import java.time.Instant;
import org.springframework.dao.DuplicateKeyException;
import jakarta.annotation.PostConstruct;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import java.time.Duration;
import java.util.Locale;

/**
 * Single active application session per principal. The unique principal key
 * is the authority; old session cookies and session-bound JWTs are rejected.
 */
@Service
public class ActiveSessionService {
  private final JdbcTemplate jdbc;
  private final SessionRepository<?> sessions;
  private final Duration absoluteLifetime;

  public ActiveSessionService(JdbcTemplate jdbc, SessionRepository<?> sessions,
      @Value("${app.session.absolute-lifetime:PT8H}") Duration absoluteLifetime) {
    this.jdbc = jdbc;
    this.sessions = sessions;
    this.absoluteLifetime = absoluteLifetime;
  }

  @PostConstruct
  public void initializeSchema() {
    jdbc.execute("CREATE TABLE IF NOT EXISTS app_active_session (" +
        "principal VARCHAR(255) PRIMARY KEY, session_id VARCHAR(255) NOT NULL, " +
        "created_at TIMESTAMP WITH TIME ZONE NOT NULL)");
    jdbc.execute("ALTER TABLE app_active_session ADD COLUMN IF NOT EXISTS auth_method VARCHAR(20)");
    jdbc.execute("CREATE OR REPLACE VIEW app_session_readable AS " +
        "SELECT a.principal AS username, a.session_id, a.auth_method, a.created_at AS login_at, " +
        "s.last_access_time, s.max_inactive_interval, " +
        "s.last_access_time + CAST(s.max_inactive_interval AS BIGINT) * 1000 AS idle_expires_at_ms, " +
        "s.expiry_time AS spring_session_expires_at_ms " +
        "FROM app_active_session a LEFT JOIN spring_session s ON s.session_id = a.session_id");
  }

  public void register(String principal, String sessionId) {
    register(principal, sessionId, "LOCAL");
  }

  public void register(String principal, String sessionId, String authenticationMethod) {
    String method = authenticationMethod == null ? "UNKNOWN" : authenticationMethod.toUpperCase(Locale.ROOT);
    if (!java.util.Set.of("LOCAL", "SAML", "OAUTH2", "OIDC", "UNKNOWN").contains(method)) {
      throw new IllegalArgumentException("Unsupported authentication method");
    }
    String previous = jdbc.query(
        "select session_id from app_active_session where principal = ?",
        rs -> rs.next() ? rs.getString(1) : null, principal);
    int updated = jdbc.update(
        "update app_active_session set session_id = ?, created_at = ?, auth_method = ? where principal = ?",
        sessionId, Instant.now(), method, principal);
    if (updated == 0) {
      try {
        jdbc.update("insert into app_active_session(principal, session_id, created_at, auth_method) values(?,?,?,?)",
            principal, sessionId, Instant.now(), method);
      } catch (DuplicateKeyException concurrentLogin) {
        jdbc.update("update app_active_session set session_id = ?, created_at = ?, auth_method = ? where principal = ?",
            sessionId, Instant.now(), method, principal);
      }
    }
    if (previous != null && !previous.equals(sessionId)) {
      sessions.deleteById(previous);
    }
  }

  public boolean isActive(String principal, String sessionId) {
    if (principal == null || sessionId == null) return false;
    var records = jdbc.query(
        "select session_id, created_at from app_active_session where principal = ?",
        (rs, row) -> new SessionRecord(rs.getString(1),
            rs.getTimestamp(2).toInstant()), principal);
    if (records.isEmpty()) return false;
    SessionRecord record = records.get(0);
    if (!record.sessionId().equals(sessionId)) return false;
    if (!record.createdAt().plus(absoluteLifetime).isAfter(Instant.now())) {
      revoke(principal, sessionId);
      return false;
    }
    return true;
  }

  private record SessionRecord(String sessionId, Instant createdAt) {}

  public void revoke(String principal, String sessionId) {
    jdbc.update("delete from app_active_session where principal = ? and session_id = ?",
        principal, sessionId);
    sessions.deleteById(sessionId);
  }
}
