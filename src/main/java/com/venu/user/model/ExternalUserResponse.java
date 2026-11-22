package com.venu.user.model;

public record ExternalUserResponse(
    Long id,
    String name,
    String username,
    String email,
    String phone,
    String website
) {}
