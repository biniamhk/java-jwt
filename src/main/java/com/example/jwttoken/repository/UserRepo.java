package com.example.jwttoken.repository;

import com.example.jwttoken.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;


public interface UserRepo extends JpaRepository<AppUser,Long> {
    AppUser findByUserName(String userName);
}
