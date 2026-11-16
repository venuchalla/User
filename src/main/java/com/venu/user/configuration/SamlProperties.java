package com.venu.user.configuration;

import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "app")
@Getter
@Setter
public class SamlProperties {

  private Map<String, CallbackConfig> callbacks;

  @Getter
  @Setter
  public static class CallbackConfig {
    private String successUrl;
    private String errorUrl;
    private String logoutUrl;
  }
}
