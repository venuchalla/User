package com.venu.user.clients;

import com.venu.user.model.ExternalUserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

@FeignClient(
    name = "jsonPlaceholderClient",
    url = "${external.api.jsonplaceholder.url}"
)
public interface JsonPlaceholderClient {

    @GetMapping("/users")
    List<ExternalUserResponse> getAllUsers();

    @GetMapping("/users/{id}")
    ExternalUserResponse getUserById(
        @PathVariable("id") Long id
    );
}
