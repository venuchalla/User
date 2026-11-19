package com.venu.user.entities;

import com.github.f4b6a3.ulid.UlidCreator;
import jakarta.persistence.*;
import java.util.List;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity()
@Table(name = "Profile")
@Getter
@Setter
@NoArgsConstructor
public class Profile {
  @Id private String profileId;
  private String firstName;
  private String lastName;
  private String email;

  @ManyToMany
  @JoinTable(
      name = "profile_address",
      joinColumns = @JoinColumn(name = "profile_id"),
      inverseJoinColumns = @JoinColumn(name = "address_id"))
  private List<Address> addresses;

  @PrePersist
  public void prePersist() {
    this.profileId = UlidCreator.getUlid().toString();
  }
}
