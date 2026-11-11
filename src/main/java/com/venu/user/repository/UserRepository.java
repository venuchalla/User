package com.venu.user.repository;

import com.venu.user.model.User;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  @Query("SELECT u FROM User u WHERE u.lastName=?1")
  List<User> findUsersWithLastName(String lastName);

  // LIKE CONCAT('%',:username,'%')")
  @Query("SELECT u FROM User u WHERE u.lastName LIKE CONCAT('%',:inputString,'%')")
  List<User> findUsersWithLastNameWhichMathcesInputString(String inputString);
}
