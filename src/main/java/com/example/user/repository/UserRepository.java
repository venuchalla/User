package com.example.user.repository;

import com.example.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.lastName=?1")
    List<User> findUsersWithLastName(String lastName);

    //LIKE CONCAT('%',:username,'%')")
    @Query("SELECT u FROM User u WHERE u.lastName LIKE CONCAT('%',:inputString,'%')")
    List<User> findUsersWithLastNameWhichMathcesInputString(String inputString);
}
