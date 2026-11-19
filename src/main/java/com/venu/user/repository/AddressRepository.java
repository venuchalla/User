package com.venu.user.repository;

import com.venu.user.entities.Address;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

@Repository
@RepositoryRestResource(path = "addresses")
public interface AddressRepository extends JpaRepository<Address, String> {}
