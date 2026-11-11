package com.venu.user;

import com.venu.user.security.JwtUtils;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class UserApplicationTests {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtUtils jwtUtils;

	@Test
	void contextLoads() {
	}

	@Test
	void seededAccountsCanAuthenticateWithTheirRoles() {
		assertAccountAuthenticates("user", "User123!", "USER");
		assertAccountAuthenticates("alice", "Alice123!", "USER");
		assertAccountAuthenticates("bob", "Bob123!", "USER");
		assertAccountAuthenticates("moderator", "Moderator123!", "MODERATOR");
		assertAccountAuthenticates("admin", "Admin123!", "ADMIN");
	}

	private void assertAccountAuthenticates(String username, String password, String role) {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(username, password));

		assertTrue(authentication.getAuthorities().stream()
				.anyMatch(authority -> authority.getAuthority().equals(role)));

		String token = jwtUtils.generateJwtToken(authentication);
		assertTrue(jwtUtils.validateJwtToken(token));
		assertTrue(jwtUtils.getUserNameFromJwtToken(token).equals(username));
	}
}
