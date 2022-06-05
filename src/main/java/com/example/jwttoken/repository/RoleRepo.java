package com.example.jwttoken.repository;

import com.example.jwttoken.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface RoleRepo extends JpaRepository<Role, Long> {
    Role findByName(String name);
    Optional<Role> findById(Long id);
}
