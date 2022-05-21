package com.example.jwttoken.service;



import com.example.jwttoken.domain.AppUser;
import com.example.jwttoken.domain.Role;

import java.util.List;

public interface AppUserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUser();
}
