package com.venu.user.utils;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class UrlUtils {

  private UrlUtils() {}

  public static String getOrigin(HttpServletRequest request) {
    String scheme = request.getScheme();
    String host = request.getServerName();
    int port = request.getServerPort();

    boolean defaultPort =
        ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);

    String s = defaultPort ? scheme + "://" + host : scheme + "://" + host + ":" + port;
    log.info("front end request url : {}", s);
    return s;
  }
}
