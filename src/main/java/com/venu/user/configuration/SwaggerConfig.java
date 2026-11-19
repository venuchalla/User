package com.venu.user.configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "User Service API",
                version = "1.0",
                description = "User Management APIs",
                contact = @Contact(
                        name = "Venu",
                        email = "venu@example.com"
                )
        )
)
public class SwaggerConfig {}
