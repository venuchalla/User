package com.venu.user.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.venu.user.configuration.SamlConfig;
import com.venu.user.model.CallBackUrls;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpServletRequest;

class SamlAppContextServiceTests {
  private SamlAppContextService service;

  @BeforeEach
  void setup() {
    DriverManagerDataSource dataSource =
        new DriverManagerDataSource(
            "jdbc:h2:mem:saml-app-context-" + java.util.UUID.randomUUID() + ";DB_CLOSE_DELAY=-1",
            "sa",
            "");
    dataSource.setDriverClassName("org.h2.Driver");
    SamlConfig config = mock(SamlConfig.class);
    when(config.getAppUrls("angular"))
        .thenReturn(
            new CallBackUrls(
                "https://frontend.example/profile",
                "https://frontend.example/error",
                "https://frontend.example/logout"));
    service =
        new SamlAppContextService(
            new JdbcTemplate(dataSource), config, new DataSourceTransactionManager(dataSource));
    service.initialize();
  }

  @Test
  void loginStoresAppIdAndSuccessKeepsItInSession() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    service.startLogin(request, "angular");
    assertEquals(Optional.of("angular"), service.pendingLoginApp(request));
    assertEquals("angular", request.getSession().getAttribute("RelayState"));
    service.finishLogin(request, "angular");
    assertEquals(Optional.empty(), service.pendingLoginApp(request));
    assertEquals(Optional.of("angular"), service.authenticatedApp(request));
    assertNull(request.getSession().getAttribute("RelayState"));
  }

  @Test
  void rejectsUnknownAppAndMismatchedCompletion() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    assertThrows(IllegalArgumentException.class, () -> service.startLogin(request, "unknown"));
    service.startLogin(request, "angular");
    assertThrows(IllegalStateException.class, () -> service.finishLogin(request, "other"));
  }

  @Test
  void logoutStateSurvivesSessionInvalidationAndIsSingleUse() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    service.startLogin(request, "angular");
    service.finishLogin(request, "angular");
    String state = service.prepareLogout(request);
    request.getSession().invalidate();
    assertEquals(Optional.of("angular"), service.consumeLogout(state));
    assertEquals(Optional.empty(), service.consumeLogout(state));
  }

  @Test
  void invalidLogoutStateIsRejected() {
    assertEquals(Optional.empty(), service.consumeLogout(null));
    assertEquals(Optional.empty(), service.consumeLogout("unknown"));
    assertThrows(
        IllegalStateException.class, () -> service.prepareLogout(new MockHttpServletRequest()));
  }
}
