package com.venu.user.repository;

import com.venu.user.entities.Profile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

@Repository
@RepositoryRestResource(path = "profiles")
public interface ProfileRepository extends JpaRepository<Profile, String> {}
