package com.venu.user.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

class ZitadelLogoutResponseValidatorTests {
  private static final String REQUEST_ID = "_logout-request";
  private static final String IDP_ENTITY_ID = "https://idp.example/metadata";
  private static final String SP_SLO_URL = "https://sp.example/saml/slo";

  @Test
  void acceptsUnsignedPostResponseWhenCorrelationAndStatusAreValid() {
    var result = validate(responseXml(REQUEST_ID, successStatus()), false);

    assertFalse(result.hasErrors());
  }

  @Test
  void rejectsUnsignedPostResponseWithMismatchedRequestId() {
    var result = validate(responseXml("_other-request", successStatus()), false);

    assertTrue(result.hasErrors());
  }

  @Test
  void rejectsUnsignedPostResponseWhenIdpReportsFailure() {
    var result =
        validate(
            responseXml(
                REQUEST_ID,
                "<saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:RequestDenied\"/>"),
            false);

    assertTrue(result.hasErrors());
  }

  @Test
  void rejectsUnsignedPostResponseWhenSignatureIsRequired() {
    var result = validate(responseXml(REQUEST_ID, successStatus()), true);

    assertTrue(result.hasErrors());
  }

  private Saml2LogoutResponseValidatorParameters parameters(String responseXml) {
    RelyingPartyRegistration registration =
        RelyingPartyRegistration.withRegistrationId("zitadel")
            .entityId("https://sp.example/metadata")
            .assertionConsumerServiceLocation("https://sp.example/acs")
            .singleLogoutServiceLocation(SP_SLO_URL)
            .singleLogoutServiceResponseLocation(SP_SLO_URL)
            .assertingPartyMetadata(
                party ->
                    party
                        .entityId(IDP_ENTITY_ID)
                        .singleSignOnServiceLocation("https://idp.example/sso")
                        .singleLogoutServiceLocation("https://idp.example/slo")
                        .singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT))
            .build();
    String encoded =
        Base64.getEncoder().encodeToString(responseXml.getBytes(StandardCharsets.UTF_8));
    var response =
        Saml2LogoutResponse.withRelyingPartyRegistration(registration)
            .binding(Saml2MessageBinding.POST)
            .samlResponse(encoded)
            .build();
    var request =
        Saml2LogoutRequest.withRelyingPartyRegistration(registration).id(REQUEST_ID).build();
    return new Saml2LogoutResponseValidatorParameters(response, request, registration);
  }

  private org.springframework.security.saml2.provider.service.authentication.logout
          .Saml2LogoutValidatorResult
      validate(String xml, boolean signatureRequired) {
    return new ZitadelLogoutResponseValidator(signatureRequired).validate(parameters(xml));
  }

  private String responseXml(String inResponseTo, String status) {
    return """
        <saml2p:LogoutResponse xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_logout-response" InResponseTo="%s" Version="2.0"
            Destination="%s">
          <saml2:Issuer>%s</saml2:Issuer>
          <saml2p:Status>%s</saml2p:Status>
        </saml2p:LogoutResponse>
        """
        .formatted(inResponseTo, SP_SLO_URL, IDP_ENTITY_ID, status);
  }

  private String successStatus() {
    return "<saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>";
  }
}
