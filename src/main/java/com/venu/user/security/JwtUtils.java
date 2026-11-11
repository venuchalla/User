package com.venu.user.security;

import com.venu.user.model.CreditionalDetailsImpl;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  private final SecretKey key;
  private final int jwtExpirationMs;

  public JwtUtils(
      @Value("${app.jwtSecret}") String jwtSecret,
      @Value("${app.jwtExpirationMs}") int jwtExpirationMs) {

    byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);

    if (keyBytes.length < 32) {
      throw new IllegalArgumentException("JWT secret must contain at least 32 bytes for HS256");
    }

    this.key = Keys.hmacShaKeyFor(keyBytes);
    this.jwtExpirationMs = jwtExpirationMs;
  }

  public String generateJwtToken(Authentication authentication) {

    CreditionalDetailsImpl userPrincipal = (CreditionalDetailsImpl) authentication.getPrincipal();

    return Jwts.builder()
        .subject((userPrincipal.getUsername()))
        .issuedAt(new Date())
        .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(key, Jwts.SIG.HS256)
        .compact();
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser().verifyWith(key).build().parseClaimsJws(authToken);
      // parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
}
