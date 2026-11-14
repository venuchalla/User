package com.venu.user;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.venu.user.security.JwtUtils;
import com.venu.user.security.SamlLogoutSuccessHandler;
import com.venu.user.security.SamlProfile;
import com.venu.user.security.SamlTicketStore;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "app.saml.enabled=false")
@AutoConfigureMockMvc
@ActiveProfiles("local")
class UserApplicationTests {

  @Autowired private AuthenticationManager authenticationManager;

  @Autowired private JwtUtils jwtUtils;

  @Autowired private MockMvc mockMvc;

  @Autowired private SamlTicketStore samlTicketStore;

  @Value("${app.saml.acs-url}")
  private String acsUrl;

  @Value("${app.saml.slo-url}")
  private String sloUrl;

  @Test
  void contextLoads() {}

  @Test
  void publicHealthEndpointReturnsUpStatus() throws Exception {
    mockMvc
        .perform(get("/public/health"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status", is("UP")));
  }

  @Test
  void samlLoginExplainsWhenMetadataHasNotBeenConfigured() throws Exception {
    mockMvc.perform(get("/saml/login")).andExpect(status().isServiceUnavailable());
  }

  @Test
  void samlServiceProviderMetadataIsAvailableWhileLoginIsDisabled() throws Exception {
    mockMvc
        .perform(get("/saml2/metadata/zitadel"))
        .andExpect(status().isOk())
        .andExpect(
            org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                .contentTypeCompatibleWith("application/xml"))
        .andExpect(
            org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                .string(org.hamcrest.Matchers.containsString(acsUrl)))
        .andExpect(
            org.springframework.test.web.servlet.result.MockMvcResultMatchers.content()
                .string(
                    org.hamcrest.Matchers.containsString("ResponseLocation=\"" + sloUrl + "\"")));
  }

  @Test
  void samlProfileTicketsAreSingleUse() throws Exception {
    String ticket =
        samlTicketStore.issue(
            new SamlProfile(
                "https://idp.example", "alice", null, null, Map.of("email", "alice@example.com")));

    mockMvc
        .perform(get("/saml/profile-data").param("ticket", ticket))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.nameID", is("alice")))
        .andExpect(jsonPath("$.attributes.email", is("alice@example.com")));

    mockMvc
        .perform(get("/saml/profile-data").param("ticket", ticket))
        .andExpect(status().isNotFound());
  }

  @Test
  void samlProfileAllowsTheConfiguredAngularOrigin() throws Exception {
    mockMvc
        .perform(
            options("/saml/profile-data")
                .header("Origin", "https://localhost:4200")
                .header("Access-Control-Request-Method", "GET"))
        .andExpect(status().isOk())
        .andExpect(header().string("Access-Control-Allow-Origin", "https://localhost:4200"))
        .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
  }

  @Test
  void userApiAllowsLocalAngularOrigins() throws Exception {
    for (String origin : List.of("http://localhost:4200", "https://localhost:4200")) {
      mockMvc
          .perform(
              options("/auth/signin")
                  .header("Origin", origin)
                  .header("Access-Control-Request-Method", "POST")
                  .header("Access-Control-Request-Headers", "authorization,content-type"))
          .andExpect(status().isOk())
          .andExpect(header().string("Access-Control-Allow-Origin", origin))
          .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }
  }

  @Test
  void samlLogoutAllowsPostFromTheConfiguredAngularOrigin() throws Exception {
    mockMvc
        .perform(
            options("/saml/logout")
                .header("Origin", "https://localhost:4200")
                .header("Access-Control-Request-Method", "POST"))
        .andExpect(status().isOk())
        .andExpect(header().string("Access-Control-Allow-Origin", "https://localhost:4200"))
        .andExpect(
            header()
                .string(
                    "Access-Control-Allow-Methods", org.hamcrest.Matchers.containsString("POST")));
  }

  @Test
  void samlLogoutResponseAllowsPostFromTheConfiguredIdentityProviderOrigin() throws Exception {
    mockMvc
        .perform(
            options("/saml/slo")
                .header("Origin", "https://my-dev-authentication-server-dsealt.us1.zitadel.cloud")
                .header("Access-Control-Request-Method", "POST"))
        .andExpect(status().isOk())
        .andExpect(
            header()
                .string(
                    "Access-Control-Allow-Origin",
                    "https://my-dev-authentication-server-dsealt.us1.zitadel.cloud"))
        .andExpect(
            header()
                .string(
                    "Access-Control-Allow-Methods", org.hamcrest.Matchers.containsString("POST")));
  }

  @Test
  void successfulSamlLogoutRedirectsToAngularCompletionRoute() throws Exception {
    MockHttpServletResponse response = new MockHttpServletResponse();

    new SamlLogoutSuccessHandler("https://localhost:4200/saml/logout-complete")
        .onLogoutSuccess(new MockHttpServletRequest(), response, null);

    assertEquals("https://localhost:4200/saml/logout-complete", response.getRedirectedUrl());
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
    Authentication authentication =
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password));

    assertTrue(
        authentication.getAuthorities().stream()
            .anyMatch(authority -> authority.getAuthority().equals(role)));

    String token = jwtUtils.generateJwtToken(authentication);
    assertTrue(jwtUtils.validateJwtToken(token));
    assertTrue(jwtUtils.getUserNameFromJwtToken(token).equals(username));
  }
}
