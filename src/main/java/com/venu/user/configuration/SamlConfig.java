package com.venu.user.configuration;

import com.venu.user.model.CallBackUrls;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class SamlConfig {

  private final SamlProperties samlProperties;

  public CallBackUrls getAppUrls(String appId) {

    if (appId != null && !appId.isEmpty()) {
      SamlProperties.CallbackConfig config = samlProperties.getCallbacks().get(appId);
      if (config == null) {
        return null;
      }
      return new CallBackUrls(config.getSuccessUrl(), config.getErrorUrl(), config.getLogoutUrl());
    } else {
      SamlProperties.CallbackConfig config = samlProperties.getCallbacks().get("default");
      if (config == null) {
        return null;
      }
      return new CallBackUrls(config.getSuccessUrl(), config.getErrorUrl(), config.getLogoutUrl());
    }
  }
}
