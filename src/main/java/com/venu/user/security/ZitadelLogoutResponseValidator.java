package com.venu.user.security;

import java.io.ByteArrayInputStream;
import java.util.Base64;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSaml4LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

final class ZitadelLogoutResponseValidator {
  private static final String PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";
  private static final String ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
  private static final String SIGNATURE_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";
  private static final String SUCCESS_STATUS = "urn:oasis:names:tc:SAML:2.0:status:Success";

  private final boolean signatureRequired;
  private final OpenSaml4LogoutResponseValidator signedResponseValidator =
      new OpenSaml4LogoutResponseValidator();

  ZitadelLogoutResponseValidator(boolean signatureRequired) {
    this.signatureRequired = signatureRequired;
  }

  Saml2LogoutValidatorResult validate(Saml2LogoutResponseValidatorParameters parameters) {
    var response = parameters.getLogoutResponse();
    if (response.getBinding() != Saml2MessageBinding.POST) {
      return error(
          Saml2ErrorCodes.INVALID_RESPONSE, "Unsigned LogoutResponse is only accepted with POST");
    }

    Element root;
    try {
      byte[] decoded = Base64.getDecoder().decode(response.getSamlResponse());
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      factory.setXIncludeAware(false);
      factory.setExpandEntityReferences(false);
      root =
          factory
              .newDocumentBuilder()
              .parse(new ByteArrayInputStream(decoded))
              .getDocumentElement();
    } catch (Exception exception) {
      return error(
          Saml2ErrorCodes.INVALID_RESPONSE,
          "Unable to parse the SAML LogoutResponse: " + exception.getClass().getSimpleName());
    }

    if (!"LogoutResponse".equals(root.getLocalName())
        || !PROTOCOL_NAMESPACE.equals(root.getNamespaceURI())) {
      return error(Saml2ErrorCodes.INVALID_RESPONSE, "Expected a SAML 2.0 LogoutResponse");
    }

    if (hasSignature(root)) {
      return this.signedResponseValidator.validate(parameters);
    }
    if (this.signatureRequired) {
      return error(Saml2ErrorCodes.INVALID_SIGNATURE, "LogoutResponse signature is required");
    }

    var registration = parameters.getRelyingPartyRegistration();
    var request = parameters.getLogoutRequest();
    if (!request.getId().equals(root.getAttribute("InResponseTo"))) {
      return error(
          Saml2ErrorCodes.INVALID_RESPONSE,
          "LogoutResponse InResponseTo does not match the LogoutRequest ID");
    }
    if (!registration
        .getSingleLogoutServiceResponseLocation()
        .equals(root.getAttribute("Destination"))) {
      return error(
          Saml2ErrorCodes.INVALID_DESTINATION,
          "LogoutResponse destination does not match the configured SLO response URL");
    }
    Element issuer = directChild(root, ASSERTION_NAMESPACE, "Issuer");
    if (issuer == null
        || !registration
            .getAssertingPartyMetadata()
            .getEntityId()
            .equals(issuer.getTextContent().trim())) {
      return error(Saml2ErrorCodes.INVALID_ISSUER, "LogoutResponse issuer does not match the IdP");
    }
    Element status = directChild(root, PROTOCOL_NAMESPACE, "Status");
    Element statusCode =
        status == null ? null : directChild(status, PROTOCOL_NAMESPACE, "StatusCode");
    if (statusCode == null || !SUCCESS_STATUS.equals(statusCode.getAttribute("Value"))) {
      return error(
          Saml2ErrorCodes.INVALID_RESPONSE, "IdP did not return a successful logout status");
    }

    return Saml2LogoutValidatorResult.success();
  }

  private boolean hasSignature(Element root) {
    return directChild(root, SIGNATURE_NAMESPACE, "Signature") != null;
  }

  private Element directChild(Element parent, String namespace, String localName) {
    for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
      if (child instanceof Element element
          && localName.equals(element.getLocalName())
          && namespace.equals(element.getNamespaceURI())) {
        return element;
      }
    }
    return null;
  }

  private Saml2LogoutValidatorResult error(String code, String description) {
    return Saml2LogoutValidatorResult.withErrors(new Saml2Error(code, description)).build();
  }
}
