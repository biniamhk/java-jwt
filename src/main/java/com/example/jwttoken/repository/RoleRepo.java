package com.example.jwttoken.repository;

import com.example.jwttoken.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
