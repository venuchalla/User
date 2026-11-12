package com.venu.user.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.stereotype.Component;

@Component
public class SamlDebugListener {

  private static final Logger log = LoggerFactory.getLogger(SamlDebugListener.class);

  @EventListener
  public void failure(AbstractAuthenticationFailureEvent event) {

    log.error("AUTH FAILURE EVENT", event.getException());
  }
}
