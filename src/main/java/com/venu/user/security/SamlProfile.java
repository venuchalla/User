package com.venu.user.security;

import java.util.Map;

public record SamlProfile(
        String issuer,
        String nameID,
        String nameIDFormat,
        String sessionIndex,
        Map<String, Object> attributes) {
}
