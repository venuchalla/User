package com.example.user.service;

import com.example.user.model.User;
import com.example.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;

    public Optional<User> getUserBasedOnId(Long id) {
        return userRepository.findById(id);
    }

    public User saveUser(User user){
        return userRepository.save(user);
    }

    @Override
    public List<User> getUserWithLastName(String lastName) {
        return userRepository.findUsersWithLastName(lastName) ;
    }

    @Override
    public List<User> getUserWithLastNameMatchesWithInputString(String inputString) {
        return userRepository.findUsersWithLastNameWhichMathcesInputString(inputString);
    }

}
