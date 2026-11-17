package com.venu.user.controlleradvices;

import com.venu.user.model.Error;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Error> handleValidationException(MethodArgumentNotValidException ex) {

    Map<String, String> errors = new HashMap<>();

    ex.getBindingResult()
        .getFieldErrors()
        .forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));

    Error response =
        new Error("VALIDATION_ERROR", "Input validation failed", LocalDateTime.now(), errors);

    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<Error> handle(Exception ex) {
    String s = returnStringFromException(ex);
    Error response =
        new Error("UNKNOWN_EXCEPTION", ex.getMessage(), LocalDateTime.now(), Map.of("ex", s));
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<Error> handleBadCredentials(Exception ex) {
    String s = returnStringFromException(ex);
    Error response =
        new Error("BAD_CREDENTIALS", ex.getMessage(), LocalDateTime.now(), Map.of("ex", s));
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
  }

  private String returnStringFromException(Exception ex) {
    String s =
        Arrays.stream(ex.getStackTrace())
            .limit(5)
            .map(StackTraceElement::toString)
            .collect(Collectors.joining("\n"));

    log.error("Exception occurred : {}", s);
    return s;
  }
}
