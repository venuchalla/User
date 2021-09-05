package com.example.user.model;

import lombok.*;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter(AccessLevel.PUBLIC)
@Setter(AccessLevel.PUBLIC)
public class UserPage {
    private List<User> users;
    private int currentPageIndex;
    private int usersInCurrentPage;
    private int totalPages;
    private Long totalUsers;

}
