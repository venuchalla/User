package com.venu.user.service;

import com.venu.user.model.User;
import com.venu.user.model.UserPage;
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
