package com.example.user.service;

import com.example.user.model.User;

import java.util.List;
import java.util.Optional;


public interface UserService {
    Optional<User> getUserBasedOnId(Long id);

    User saveUser(User user);

    List<User> getUserWithLastName(String LastName);

    List<User> getUserWithLastNameMatchesWithInputString(String inputString);


}
