package com.venu.user.security;

import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretVersionName;
import com.venu.user.configuration.SamlConfig;
import com.venu.user.model.CallBackUrls;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml4MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml4AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.metadata.RequestMatcherMetadataResponseResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;

@Configuration
@ConditionalOnProperty(name = "app.saml.enabled", havingValue = "true")
@RequiredArgsConstructor
public class SamlSecurityConfiguration {
  private static final Logger logger = LoggerFactory.getLogger(SamlSecurityConfiguration.class);
  private static final String SAML_ENCODING =
      "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";
  private static final String SAML_NAME_ID_FORMAT =
      "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
  private @Value("${app.saml.registration-id}") String registrationId;
  private final SamlConfig samlConfig;

  @Bean
  RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(
      @Value("${app.saml.idp-metadata-uri}") String metadataUri,
      @Value("${app.saml.sp-entity-id}") String spEntityId,
      @Value("${app.saml.acs-url}") String acsUrl,
      @Value("${app.saml.slo-url}") String sloUrl,
      @Value("${app.saml.sp-private-key-location}") String privateKeyLocation,
      @Value("${app.saml.sp-certificate-location}") String certificateLocation,
      ResourceLoader resourceLoader)
      throws Exception {
    PrivateKey privateKey = readPrivateKey(privateKeyLocation, resourceLoader);
    X509Certificate certificate = readCertificate(certificateLocation, resourceLoader);
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
                    assertingParty.singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT))
            .authnRequestsSigned(true)
            .signingX509Credentials(credentials -> credentials.add(signingCredential))
            .build();
    return new InMemoryRelyingPartyRegistrationRepository(registration);
  }

  private PrivateKey readPrivateKey(String location, ResourceLoader resourceLoader)
      throws Exception {
    String pem =
        new String(readConfiguredBytes(location, resourceLoader), StandardCharsets.UTF_8)
            .replaceAll("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
    byte[] keyBytes = Base64.getDecoder().decode(pem);
    return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
  }

  private X509Certificate readCertificate(String location, ResourceLoader resourceLoader)
      throws Exception {
    try (InputStream input =
        new ByteArrayInputStream(readConfiguredBytes(location, resourceLoader))) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
    }
  }

  private byte[] readConfiguredBytes(String location, ResourceLoader resourceLoader)
      throws Exception {
    if (location.startsWith("projects/")) {
      String[] path = location.split("/");
      if (path.length != 4 || !"projects".equals(path[0]) || !"secrets".equals(path[2])) {
        throw new IllegalArgumentException("Invalid Google Secret Manager resource: " + location);
      }
      SecretVersionName secretVersion = SecretVersionName.of(path[1], path[3], "latest");
      try (SecretManagerServiceClient client = SecretManagerServiceClient.create()) {
        return client.accessSecretVersion(secretVersion).getPayload().getData().toByteArray();
      }
    }

    try (InputStream input = resourceLoader.getResource(location).getInputStream();
        ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      input.transferTo(output);
      return output.toByteArray();
    }
  }

  @Bean
  @Order(1)
  SecurityFilterChain samlSecurityFilterChain(
      HttpSecurity http,
      AuthTokenFilter authTokenFilter,
      SamlAuthenticationSuccessHandler successHandler,
      ActiveSessionService activeSessions,
      SamlAppContextService appContext,
      RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
      Saml2MetadataResponseResolver saml2MetadataResponseResolver,
      @Value("${app.saml.force-authn:true}") boolean forceAuthn,
      @Value("${app.saml.logout-issue-instant-offset-seconds:-5}")
          long logoutIssueInstantOffsetSeconds,
      @Value("${app.saml.logout-response-signature-required:false}")
          boolean logoutResponseSignatureRequired)
      throws Exception {

    OpenSaml4AuthenticationRequestResolver authenticationRequestResolver =
        new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationRepository);
    authenticationRequestResolver.setAuthnRequestCustomizer(
        context -> context.getAuthnRequest().setForceAuthn(forceAuthn));
    authenticationRequestResolver.setRelayStateResolver(
        request -> {
          return appContext.pendingLoginApp(request).orElse(null);
        });
    LogoutSuccessHandler samlLogoutSuccessHandler =
        new SamlLogoutSuccessHandler(samlConfig, appContext);

    http.cors(Customizer.withDefaults())
        .csrf(AbstractHttpConfigurer::disable)
        .securityMatcher(
            "/saml/**", "/saml2/**", "/login/**", "/logout/saml2/**", "/error", "/favicon.ico")
        .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
        .sessionManagement(
            session ->
                session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation(fixation -> fixation.changeSessionId()))
        .saml2Login(
            saml ->
                saml.authenticationRequestResolver(authenticationRequestResolver)
                    .successHandler(successHandler)
                    .failureHandler(
                        (request, response, exception) -> {
                          var session = request.getSession(false);
                          String appId = appContext.pendingLoginApp(request).orElse(null);
                          CallBackUrls callBackUrls = samlConfig.getAppUrls(appId);
                          logger.warn(
                              "SAML authentication failed; reason={}",
                              exception.getClass().getSimpleName());
                          if (callBackUrls == null) {
                            response.sendError(401, "SAML authentication failed");
                            return;
                          }
                          new SimpleUrlAuthenticationFailureHandler(callBackUrls.errorUrl())
                              .onAuthenticationFailure(request, response, exception);
                        }))
        .saml2Logout(
            saml ->
                saml.logoutUrl("/saml/logout")
                    .logoutRequest(
                        request ->
                            request.logoutRequestResolver(
                                (httpRequest, authentication) -> {
                                  // logger.info("appId======== in LOGout  auth:{} {}{}",
                                  // authentication.getDetails(),authentication.getPrincipal(),authentication.getCredentials());
                                  //   logger.info("appId========
                                  // {}",httpRequest.getSession().getId());
                                  OpenSaml4LogoutRequestResolver logoutRequestResolver =
                                      new OpenSaml4LogoutRequestResolver(
                                          relyingPartyRegistrationRepository);

                                  logoutRequestResolver.setClock(
                                      Clock.offset(
                                          Clock.systemUTC(),
                                          Duration.ofSeconds(logoutIssueInstantOffsetSeconds)));

                                  logoutRequestResolver.setParametersConsumer(
                                      parameters -> {
                                        var logoutRequest = parameters.getLogoutRequest();

                                        var nameId = logoutRequest.getNameID();

                                        if (nameId != null) {

                                          nameId.setFormat(SAML_NAME_ID_FORMAT);

                                          logger.info(
                                              "SAML LogoutRequest NameID Format: {}",
                                              nameId.getFormat());
                                        }

                                        logger.info("LogoutRequest ID: {}", logoutRequest.getID());

                                        logger.info(
                                            "LogoutRequest Destination: {}",
                                            logoutRequest.getDestination());
                                      });
                                  logoutRequestResolver.setRelayStateResolver(
                                      r ->
                                          (String)
                                              r.getAttribute(
                                                  SamlLogoutPreparationFilter
                                                      .LOGOUT_STATE_ATTRIBUTE));
                                  var logoutRequest =
                                      logoutRequestResolver.resolve(httpRequest, authentication);
                                  if (logoutRequest != null) {
                                    logger.info(
                                        "Starting SAML single logout for registration {} using {} binding",
                                        logoutRequest.getRelyingPartyRegistrationId(),
                                        logoutRequest.getBinding().getUrn());
                                    logger.info("SAML LogoutRequest ID: {}", logoutRequest.getId());

                                    return Saml2LogoutRequest.withRelyingPartyRegistration(
                                            relyingPartyRegistrationRepository.findByRegistrationId(
                                                registrationId))
                                        .id(logoutRequest.getId())
                                        .samlRequest(logoutRequest.getSamlRequest())
                                        .relayState(logoutRequest.getRelayState())
                                        .parameters(
                                            params -> {
                                              params.putAll(logoutRequest.getParameters());
                                              params.put("SAMLEncoding", SAML_ENCODING);
                                            })
                                        .build();
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
                                      ZitadelLogoutResponseValidator logoutResponseValidator =
                                          new ZitadelLogoutResponseValidator(
                                              logoutResponseSignatureRequired);
                                      var result = logoutResponseValidator.validate(parameters);
                                      if (result.hasErrors()) {
                                        logger.error("SAML authentication failed : {}", result);
                                        logger.warn(
                                            "SAML logout response validation failed; errors={}",
                                            result.getErrors().stream()
                                                .map(Saml2Error::getErrorCode)
                                                .toList());
                                      } else {
                                        logger.info("SAML single logout response validated");
                                      }
                                      return result;
                                    })))
        .logout(logout -> logout.logoutSuccessHandler(samlLogoutSuccessHandler))
        .saml2Metadata(saml2 -> saml2.metadataResponseResolver(saml2MetadataResponseResolver))
        .addFilterBefore(
            new SamlLogoutPreparationFilter(appContext),
            org.springframework.security.web.authentication.logout.LogoutFilter.class)
        .addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterAfter(
            new ActiveSessionEnforcementFilter(activeSessions), SecurityContextHolderFilter.class);

    // .saml2Metadata(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  Saml2MetadataResponseResolver saml2MetadataResponseResolver(
      RelyingPartyRegistrationRepository registrations,
      @Value("${app.saml.slo-url}") String sloUrl) {

    OpenSaml4MetadataResolver metadataResolver = new OpenSaml4MetadataResolver();

    metadataResolver.setEntityDescriptorCustomizer(
        parameters -> {
          SPSSODescriptor sp =
              parameters.getEntityDescriptor().getSPSSODescriptor(SAMLConstants.SAML20P_NS);

          if (sp == null) {
            return;
          }

          // Remove the default SLO endpoint
          sp.getSingleLogoutServices().clear();

          // HTTP-POST
          sp.getSingleLogoutServices()
              .add(createLogoutService(SAMLConstants.SAML2_POST_BINDING_URI, sloUrl, sloUrl));

          // HTTP-Redirect
          sp.getSingleLogoutServices()
              .add(createLogoutService(SAMLConstants.SAML2_REDIRECT_BINDING_URI, sloUrl, sloUrl));
          NameIDFormat nameIDFormat =
              (NameIDFormat)
                  Objects.requireNonNull(
                          XMLObjectProviderRegistrySupport.getBuilderFactory()
                              .getBuilder(NameIDFormat.DEFAULT_ELEMENT_NAME))
                      .buildObject(NameIDFormat.DEFAULT_ELEMENT_NAME);

          nameIDFormat.setURI(SAML_NAME_ID_FORMAT);

          sp.getNameIDFormats().clear();
          sp.getNameIDFormats().add(nameIDFormat);
        });

    return new RequestMatcherMetadataResponseResolver(registrations, metadataResolver);
  }

  private SingleLogoutService createLogoutService(
      String binding, String location, String responseLocation) {
    logger.info("configuring logout endpoints ===");
    SingleLogoutService service =
        (SingleLogoutService)
            Objects.requireNonNull(
                    XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .getBuilder(SingleLogoutService.DEFAULT_ELEMENT_NAME))
                .buildObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);

    service.setBinding(binding);
    service.setLocation(location);
    service.setResponseLocation(responseLocation);

    return service;
  }
}
