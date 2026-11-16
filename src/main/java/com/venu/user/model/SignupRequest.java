package com.venu.user.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.ToString;


import java.util.Set;


public record SignupRequest(@NotBlank(message = "username is required")
                            @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters long")
                            String username,
                            @NotBlank(message = "email is required")
                            @Size(max = 50, message = "email can not exceed more than 50 characters")
                            @Email(message = "email is not valid")
                            String email,
                            @NotNull(message = "Roles are required")
                            @Size(min = 1, message = "At least one role is required")
                            Set<String> role,
                            @NotBlank(message = "password is required")
                            @Size(min = 3, max = 40, message = "password must be between 3 and 20 characters long")
                            @ToString.Exclude
                            String password) {

}
