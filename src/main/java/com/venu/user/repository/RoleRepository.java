package com.venu.user.repository;

import com.venu.user.model.Role;
import com.venu.user.model.enums.UserRole;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

@Repository
@RepositoryRestResource(exported = false)
public interface RoleRepository extends JpaRepository<Role, Long> {
  @Query("SELECT u FROM Role u WHERE u.userRole=?1")
  Optional<Role> findByName(UserRole userRole);
}
