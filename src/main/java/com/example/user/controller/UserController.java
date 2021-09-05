package com.example.user.controller;

import com.example.user.model.Greeting;
import com.example.user.model.Input;
import com.example.user.model.User;
import com.example.user.service.UserServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api")
public class UserController {
    Logger logger = LoggerFactory.getLogger(UserController.class);
    @Autowired
    UserServiceImpl userService;

    private static final String template = "Hello, %s!";
    private final AtomicLong counter = new AtomicLong();

    @GetMapping(path = "/")
    Greeting ping(@RequestParam(value = "name", defaultValue = "Welcome to user controller") String name) {
        return new Greeting(counter.incrementAndGet(), String.format(template, name));
    }

    @GetMapping(path = "/getuser/{id}", produces = {MediaType.APPLICATION_JSON_VALUE})
    User getUserUsingIdWithPathVariable(@PathVariable Long id) {
        logger.info("Getting UserInformation for id : " + id);
        Optional<User> user = userService.getUserBasedOnId(id);
        return user.orElse(new User());
    }

    @GetMapping(path = "/getuser", produces = {MediaType.APPLICATION_JSON_VALUE})
    User getUserUsingIdWithQueryParam(@RequestParam(value = "userid") Long id) {
        logger.info("Getting UserInformation for id : " + id);
        Optional<User> user = userService.getUserBasedOnId(id);
        return user.orElse(new User());
    }

    @PostMapping(path = "/saveuser", consumes = {MediaType.APPLICATION_JSON_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE})
    User saveUser(@RequestBody User user) {
        logger.info("saving user :" + user.getFirstName());
        return userService.saveUser(user);
    }

    @PostMapping(path = "/getuser", consumes = {MediaType.APPLICATION_JSON_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE})
    List<User> getUsersUsingLastName(@RequestBody Input input) {
        logger.info("Getting UserInformation for id : " + input.getLastName());
        List<User> users = userService.getUserWithLastName(input.getLastName());
        return users;
    }

    @GetMapping(path = "/getuserslastnameMatch", produces = {MediaType.APPLICATION_JSON_VALUE})
    List<User> getUsersWithLastNameString(@RequestParam(value = "lastNameContains") String input) {
        logger.info("Getting UserInformation for id : " + input);
        List<User> users = userService.getUserWithLastNameMatchesWithInputString(input);
        return users;
    }

    @PostMapping(path = "/saveallusers", consumes = {MediaType.APPLICATION_JSON_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE})
    List<User> saveUsers(@RequestBody List<User> users) {
        logger.info("we are in save all users");
        return userService.saveAllUsers(users);
    }
}
