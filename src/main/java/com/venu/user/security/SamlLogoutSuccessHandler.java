package com.venu.user.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

public class SamlLogoutSuccessHandler implements LogoutSuccessHandler {
    private static final Logger logger = LoggerFactory.getLogger(SamlLogoutSuccessHandler.class);

    private final String frontendHomeUrl;

    public SamlLogoutSuccessHandler(String frontendHomeUrl) {
        this.frontendHomeUrl = frontendHomeUrl;
    }

    @Override
    public void onLogoutSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        logger.info("SAML logout succeeded; redirecting browser to the frontend completion route");
        response.sendRedirect(frontendHomeUrl);
    }
}
