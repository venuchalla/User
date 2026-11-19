package com.venu.user.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "Address")
@NoArgsConstructor
@Getter
@Setter
public class Address {
  @Id private String addressId;
  private String addressLineOne;
  private String addressLineTwo;
  private String city;
  private String state;
  private String zipCode;

  @ManyToMany(mappedBy = "addresses")
  private List<Profile> profileList;
}
