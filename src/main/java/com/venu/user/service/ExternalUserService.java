package com.venu.user.service;

import com.venu.user.clients.JsonPlaceholderClient;
import com.venu.user.model.ExternalUserResponse;
import feign.FeignException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
public class ExternalUserService {

    private final JsonPlaceholderClient client;

    public ExternalUserService(JsonPlaceholderClient client) {
        this.client = client;
    }

    public List<ExternalUserResponse> getAllUsers() {
        try {
            return client.getAllUsers();
        } catch (FeignException e) {
            throw new ResponseStatusException(
                HttpStatus.BAD_GATEWAY,
                "External user service unavailable"
            );
        }
    }

    public ExternalUserResponse getUserById(Long id) {
        try {
            return client.getUserById(id);
        } catch (FeignException.NotFound e) {
            throw new ResponseStatusException(
                HttpStatus.NOT_FOUND,
                "External user not found"
            );
        } catch (FeignException e) {
            throw new ResponseStatusException(
                HttpStatus.BAD_GATEWAY,
                "External user service unavailable"
            );
        }
    }
}
