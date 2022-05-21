package com.example.jwttoken;

import com.example.jwttoken.domain.AppUser;
import com.example.jwttoken.domain.Role;
import com.example.jwttoken.service.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtTokenApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtTokenApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(AppUserService userService){
        return args -> {
            userService.saveRole(new Role(null,"ROLE_USER"));
            userService.saveRole(new Role(null,"ROLE_ADMIN"));

            userService.saveUser(new AppUser(null,"Mary","mary20","1234",new ArrayList<>()));
            userService.saveUser(new AppUser(null,"Jhon","jhon21","1234",new ArrayList<>()));
            userService.saveUser(new AppUser(null,"Petter","petter22","1234",new ArrayList<>()));

            userService.addRoleToUser("mary20","ROLE_USER");
            userService.addRoleToUser("jhon21","ROLE_USER");
            userService.addRoleToUser("petter22","ROLE_ADMIN");
        };
    }
}
