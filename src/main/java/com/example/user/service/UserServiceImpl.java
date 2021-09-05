package com.example.user.service;

import com.example.user.model.User;
import com.example.user.model.UserPage;
import com.example.user.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;
    Logger logger = LoggerFactory.getLogger(UserServiceImpl.class);

    public Optional<User> getUserBasedOnId(Long id) {
        return userRepository.findById(id);
    }

    public User saveUser(User user) {
        return userRepository.save(user);
    }

    @Override
    public List<User> saveAllUsers(List<User> users) {
        return userRepository.saveAll(users);
    }

    @Override
    public List<User> getUserWithLastName(String lastName) {
        return userRepository.findUsersWithLastName(lastName);
    }

    @Override
    public List<User> getUserWithLastNameMatchesWithInputString(String inputString) {
        return userRepository.findUsersWithLastNameWhichMathcesInputString(inputString);
    }

    @Override
    public UserPage getUserWithPageble(Pageable pageable) {
        Page<User> pagebleUser=userRepository.findAll(pageable);
        UserPage userPage=new UserPage();
        userPage.setUsers(pagebleUser.getContent());
        userPage.setTotalPages(pagebleUser.getTotalPages());
        userPage.setTotalUsers(pagebleUser.getTotalElements());
        userPage.setUsersInCurrentPage(pagebleUser.getNumberOfElements());
        userPage.setCurrentPageIndex(pagebleUser.getNumber());
        return userPage;

    }
    public void removeAllUsers(){
        userRepository.deleteAll();
    }


}
