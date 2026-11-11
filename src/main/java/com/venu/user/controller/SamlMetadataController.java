package com.venu.user.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/saml2/metadata")
@ConditionalOnProperty(name = "app.saml.enabled", havingValue = "false", matchIfMissing = true)
public class SamlMetadataController {
  private final String registrationId;
  private final String spEntityId;
  private final String acsUrl;
  private final String sloUrl;

  public SamlMetadataController(
      @Value("${app.saml.registration-id:zitadel}") String registrationId,
      @Value(
              "${app.saml.sp-entity-id:http://localhost:8082/saml2/service-provider-metadata/zitadel}")
          String spEntityId,
      @Value("${app.saml.acs-url:http://localhost:8082/login/saml2/sso/zitadel}") String acsUrl,
      @Value("${app.saml.slo-url:http://localhost:8082/saml/slo}") String sloUrl) {
    this.registrationId = registrationId;
    this.spEntityId = spEntityId;
    this.acsUrl = acsUrl;
    this.sloUrl = sloUrl;
  }

  @GetMapping(value = "/{id}", produces = MediaType.APPLICATION_XML_VALUE)
  public ResponseEntity<String> metadata(@PathVariable String id) {
    if (!registrationId.equals(id)) {
      return ResponseEntity.notFound().build();
    }

    String metadata =
        """
                <?xml version="1.0" encoding="UTF-8"?>
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                                     entityID="%s">
                  <md:SPSSODescriptor AuthnRequestsSigned="false"
                                      WantAssertionsSigned="true"
                                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:AssertionConsumerService
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="%s"
                        index="0"
                        isDefault="true"/>
                    <md:SingleLogoutService
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="%s"
                        ResponseLocation="%s"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                """
            .formatted(
                escapeXml(spEntityId), escapeXml(acsUrl), escapeXml(sloUrl), escapeXml(sloUrl));

    return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML).body(metadata);
  }

  private String escapeXml(String value) {
    return value
        .replace("&", "&amp;")
        .replace("\"", "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&apos;");
  }
}
