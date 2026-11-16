package com.venu.user.model;

import java.time.LocalDateTime;
import java.util.Map;

public record Error(String code,
                    String message,
                    LocalDateTime timestamp,
                    Map<String, String> errors) {
}
