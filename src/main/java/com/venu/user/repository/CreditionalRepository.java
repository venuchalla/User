package com.venu.user.repository;

import com.venu.user.model.Creditional;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CreditionalRepository extends JpaRepository<Creditional, Long> {
  Optional<Creditional> findByUsername(String username);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
