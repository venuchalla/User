package com.example.user.service;

import com.example.user.model.User;
import com.example.user.model.UserPage;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;


public interface UserService {
    Optional<User> getUserBasedOnId(Long id);

    User saveUser(User user);

    List<User> saveAllUsers(List<User> users);

    List<User> getUserWithLastName(String LastName);

    List<User> getUserWithLastNameMatchesWithInputString(String inputString);

    UserPage getUserWithPageble(Pageable pageable);



}
