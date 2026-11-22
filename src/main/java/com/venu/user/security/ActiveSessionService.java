package com.venu.user.security;

import java.time.Instant;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

/**
 * Single active application session per principal. The unique principal key
 * is the authority; old session cookies and session-bound JWTs are rejected.
 */
@Service
public class ActiveSessionService {
  private final JdbcTemplate jdbc;
  private final SessionRepository<?> sessions;

  public ActiveSessionService(JdbcTemplate jdbc, SessionRepository<?> sessions) {
    this.jdbc = jdbc;
    this.sessions = sessions;
  }

  public void register(String principal, String sessionId) {
    String previous = jdbc.query(
        "select session_id from app_active_session where principal = ?",
        rs -> rs.next() ? rs.getString(1) : null, principal);
    int updated = jdbc.update(
        "update app_active_session set session_id = ?, created_at = ? where principal = ?",
        sessionId, Instant.now(), principal);
    if (updated == 0) {
      try {
        jdbc.update("insert into app_active_session(principal, session_id, created_at) values(?,?,?)",
            principal, sessionId, Instant.now());
      } catch (DuplicateKeyException concurrentLogin) {
        jdbc.update("update app_active_session set session_id = ?, created_at = ? where principal = ?",
            sessionId, Instant.now(), principal);
      }
    }
    if (previous != null && !previous.equals(sessionId)) {
      sessions.deleteById(previous);
    }
  }

  public boolean isActive(String principal, String sessionId) {
    if (principal == null || sessionId == null) return false;
    Integer count = jdbc.queryForObject(
        "select count(*) from app_active_session where principal = ? and session_id = ?",
        Integer.class, principal, sessionId);
    return count != null && count == 1;
  }

  public void revoke(String principal, String sessionId) {
    jdbc.update("delete from app_active_session where principal = ? and session_id = ?",
        principal, sessionId);
    sessions.deleteById(sessionId);
  }
}
