package com.venu.user;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(
    properties = {
      "SPRING_PROFILES_INCLUDE=feign",
      "app.saml.enabled=false",
      "SAML_SP_ENTITY_ID=https://api.example.com/saml",
      "SAML_ACS_URL=https://api.example.com/login/saml2/sso/zitadel",
      "SAML_SLO_URL=https://api.example.com/saml/slo"
    })
@AutoConfigureMockMvc
@ActiveProfiles("prod")
class ProductionProfileTests {

  @Autowired private MockMvc mockMvc;

  @Autowired private Environment environment;

  @Test
  void productionProfileAllowsGitHubPages() throws Exception {
    assertTrue(environment.acceptsProfiles(org.springframework.core.env.Profiles.of("prod")));
    assertTrue(environment.acceptsProfiles(org.springframework.core.env.Profiles.of("feign")));

    mockMvc
        .perform(
            options("/auth/signin")
                .header("Origin", "https://venuchalla.github.io")
                .header("Access-Control-Request-Method", "POST")
                .header("Access-Control-Request-Headers", "authorization,content-type"))
        .andExpect(status().isOk())
        .andExpect(header().string("Access-Control-Allow-Origin", "https://venuchalla.github.io"))
        .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
  }
}
