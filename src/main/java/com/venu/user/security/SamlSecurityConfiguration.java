package com.venu.user.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml4LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml4MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.metadata.RequestMatcherMetadataResponseResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@ConditionalOnProperty(name = "app.saml.enabled", havingValue = "true")
public class SamlSecurityConfiguration {
  private static final Logger logger = LoggerFactory.getLogger(SamlSecurityConfiguration.class);

  @Bean
  RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(
      @Value("${app.saml.registration-id}") String registrationId,
      @Value("${app.saml.idp-metadata-uri}") String metadataUri,
      @Value("${app.saml.sp-entity-id}") String spEntityId,
      @Value("${app.saml.acs-url}") String acsUrl,
      @Value("${app.saml.slo-url}") String sloUrl,
      @Value("${app.saml.sp-private-key-location}") Resource privateKeyResource,
      @Value("${app.saml.sp-certificate-location}") Resource certificateResource)
      throws Exception {
    PrivateKey privateKey = readPrivateKey(privateKeyResource);
    X509Certificate certificate = readCertificate(certificateResource);
    Saml2X509Credential signingCredential = Saml2X509Credential.signing(privateKey, certificate);

    RelyingPartyRegistration registration =
        RelyingPartyRegistrations.fromMetadataLocation(metadataUri)
                .registrationId(registrationId)
                .entityId(spEntityId)
                .assertionConsumerServiceLocation(acsUrl)
                .singleLogoutServiceLocation(sloUrl)
                .singleLogoutServiceResponseLocation(sloUrl)
                .assertingPartyMetadata(
                        assertingParty ->
                                assertingParty
                                        .singleLogoutServiceBinding(Saml2MessageBinding.POST)
                )
            .authnRequestsSigned(true)
            .signingX509Credentials(credentials -> credentials.add(signingCredential))
            .build();
    return new InMemoryRelyingPartyRegistrationRepository(registration);
  }

  private PrivateKey readPrivateKey(Resource resource) throws Exception {
    String pem =
        new String(readAllBytes(resource), StandardCharsets.UTF_8)
            .replaceAll("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
    byte[] keyBytes = Base64.getDecoder().decode(pem);
    return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
  }

  private X509Certificate readCertificate(Resource resource) throws Exception {
    try (InputStream input = resource.getInputStream()) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
    }
  }

  private byte[] readAllBytes(Resource resource) throws Exception {
    try (InputStream input = resource.getInputStream();
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      input.transferTo(output);
      return output.toByteArray();
    }
  }

  @Bean
  @Order(1)
  SecurityFilterChain samlSecurityFilterChain(
      HttpSecurity http,
      SamlAuthenticationSuccessHandler successHandler,
      RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
      Saml2MetadataResponseResolver saml2MetadataResponseResolver,
      @Value("${app.saml.frontend-login-error-url}") String frontendLoginErrorUrl,
      @Value("${app.saml.frontend-logout-complete-url}") String frontendLogoutCompleteUrl)
      throws Exception {
    OpenSaml4LogoutRequestResolver logoutRequestResolver =
        new OpenSaml4LogoutRequestResolver(relyingPartyRegistrationRepository);
    LogoutSuccessHandler samlLogoutSuccessHandler =
        new SamlLogoutSuccessHandler(frontendLogoutCompleteUrl);

    http.securityMatcher(
            "/saml/**", "/saml2/**", "/login/**", "/logout/saml2/**", "/error", "/favicon.ico")
        .cors(Customizer.withDefaults())
        .csrf(csrf -> csrf.disable())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
        .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
        .saml2Login(
            saml ->
                saml.successHandler(successHandler)
                    .failureHandler(
                        (request, response, exception) -> {
                          logger.warn(
                              "SAML authentication failed; reason={}",
                              exception.getClass().getSimpleName());
                          new SimpleUrlAuthenticationFailureHandler(frontendLoginErrorUrl)
                              .onAuthenticationFailure(request, response, exception);
                        }))
        .logout(logout -> logout.logoutSuccessHandler(samlLogoutSuccessHandler))
        .saml2Logout(
            saml ->
                saml.logoutUrl("/saml/logout")
                    .logoutRequest(
                        request ->
                            request.logoutRequestResolver(
                                (httpRequest, authentication) -> {
                                  var logoutRequest =
                                      logoutRequestResolver.resolve(httpRequest, authentication);
                                  if (logoutRequest != null) {
                                    logger.info(
                                        "Starting SAML single logout for registration {} using {} binding",
                                        logoutRequest.getRelyingPartyRegistrationId(),
                                        logoutRequest.getBinding().getUrn());
                                  } else {
                                    logger.debug(
                                        "SAML logout requested without an active SAML session");
                                  }
                                  return logoutRequest;
                                }))
                    .logoutResponse(
                        response ->
                            response
                                .logoutUrl("/saml/slo")
                                .logoutResponseValidator(
                                    parameters -> {
                                      logger.info("parameters ==========: {}", parameters);
                                        return Saml2LogoutValidatorResult.success();
//                                      var result =
//                                          new OpenSaml4LogoutResponseValidator()
//                                              .validate(parameters);
//                                      if (result.hasErrors()) {
//                                        logger.error("SAML authentication failed : {}", result);
//                                        logger.warn(
//                                            "SAML logout response validation failed; errors={}",
//                                            result.getErrors().stream()
//                                                .map(error -> error.getErrorCode())
//                                                .toList());
//                                      } else {
//                                        logger.info("SAML single logout response validated");
//                                      }
//                                      return result;
                                    }))
        )
        .addFilterBefore(new SamlLogoutDiagnosticFilter(), SecurityContextHolderFilter.class)
        //.saml2Metadata(Customizer.withDefaults());
            .saml2Metadata(saml2 ->
                    saml2.metadataResponseResolver(saml2MetadataResponseResolver));

    return http.build();
  }
    @Bean
    Saml2MetadataResponseResolver saml2MetadataResponseResolver(
            RelyingPartyRegistrationRepository registrations,
            @Value("${app.saml.slo-url}") String sloUrl) {

        OpenSaml4MetadataResolver metadataResolver =
                new OpenSaml4MetadataResolver();

        metadataResolver.setEntityDescriptorCustomizer(parameters -> {

            SPSSODescriptor sp =
                    parameters.getEntityDescriptor()
                            .getSPSSODescriptor(SAMLConstants.SAML20P_NS);

            if (sp == null) {
                return;
            }

            // Remove the default SLO endpoint
            sp.getSingleLogoutServices().clear();

            // HTTP-POST
            sp.getSingleLogoutServices().add(
                    createLogoutService(
                            SAMLConstants.SAML2_POST_BINDING_URI,
                            sloUrl,
                            sloUrl));

            // HTTP-Redirect
            sp.getSingleLogoutServices().add(
                    createLogoutService(
                            SAMLConstants.SAML2_REDIRECT_BINDING_URI,
                            sloUrl,
                            sloUrl));
        });

        return new RequestMatcherMetadataResponseResolver(
                registrations,
                metadataResolver);
    }
    private SingleLogoutService createLogoutService(
            String binding,
            String location,
            String responseLocation) {
logger.info("configuring logout endpoints ===");
        SingleLogoutService service =
                (SingleLogoutService)
                        XMLObjectProviderRegistrySupport
                                .getBuilderFactory()
                                .getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME)
                                .buildObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);

        service.setBinding(binding);
        service.setLocation(location);
        service.setResponseLocation(responseLocation);

        return service;
    }
  private static final class SamlLogoutDiagnosticFilter extends OncePerRequestFilter {
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
      String path = request.getServletPath();
      return !path.equals("/saml/logout")
          && !path.equals("/saml/slo")
          && !path.equals("/logout/saml2/slo");
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
      boolean hasSamlResponse = request.getParameter("SAMLResponse") != null;
      boolean hasSamlRequest = request.getParameter("SAMLRequest") != null;
      boolean hasRelayState = request.getParameter("RelayState") != null;
      boolean hasSession = request.getSession(false) != null;
      Authentication authentication =
          org.springframework.security.core.context.SecurityContextHolder.getContext()
              .getAuthentication();

      SamlSecurityConfiguration.logger.info(
          "SAML logout endpoint request: method={}, path={}, SAMLResponse={}, "
              + "SAMLRequest={}, RelayState={}, sessionPresent={}, authenticationPresent={}",
          request.getMethod(),
          request.getServletPath(),
          hasSamlResponse,
          hasSamlRequest,
          hasRelayState,
          hasSession,
          authentication != null);
      try {
        filterChain.doFilter(request, response);
        SamlSecurityConfiguration.logger.info(
            "SAML logout endpoint completed: method={}, path={}, status={}",
            request.getMethod(),
            request.getServletPath(),
            response.getStatus());
      } catch (ServletException | IOException exception) {
        SamlSecurityConfiguration.logger.warn(
            "SAML logout endpoint failed: path={}, errorType={}",
            request.getServletPath(),
            exception.getClass().getSimpleName());
        throw exception;
      }
    }
  }
}
