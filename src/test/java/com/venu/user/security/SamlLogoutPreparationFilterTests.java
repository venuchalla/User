package com.venu.user.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;

class SamlLogoutPreparationFilterTests {
  @Test
  void preparesStateBeforeLogoutAndPassesItToResolver() throws Exception {
    SamlAppContextService appContext = mock(SamlAppContextService.class);
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml/logout");
    when(appContext.authenticatedApp(request)).thenReturn(Optional.of("angular"));
    when(appContext.prepareLogout(request)).thenReturn("one-time-state");
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = (req, res) -> assertEquals("one-time-state",
        req.getAttribute(SamlLogoutPreparationFilter.LOGOUT_STATE_ATTRIBUTE));

    new SamlLogoutPreparationFilter(appContext).doFilter(request, response, chain);
    verify(appContext).prepareLogout(request);
    assertEquals(200, response.getStatus());
  }

  @Test
  void missingAppReturnsUnauthorizedWithoutStartingLogout() throws Exception {
    SamlAppContextService appContext = mock(SamlAppContextService.class);
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml/logout");
    when(appContext.authenticatedApp(request)).thenReturn(Optional.empty());
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = (req, res) -> fail("Logout must not proceed");
    new SamlLogoutPreparationFilter(appContext).doFilter(request, response, chain);
    assertEquals(401, response.getStatus());
    verify(appContext, never()).prepareLogout(any());
  }
}
