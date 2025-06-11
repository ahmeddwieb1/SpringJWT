package org.springjson;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springjson.Service.UserService;
import org.springjson.domain.Role;
import org.springjson.domain.User;

import java.util.ArrayList;

@SpringBootApplication
public class SpringJsonApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringJsonApplication.class, args);
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService){
        return args -> {
            userService.saveRole(new Role(null,"ROLE_USER"));
            userService.saveRole(new Role(null,"ROLE_MANAGER"));
            userService.saveRole(new Role(null,"ROLE_ADMIN"));
            userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));

            userService.saveuser(new User(null,"ahmed","ahmed@","1234",new ArrayList<>()));
            userService.saveuser(new User(null,"dina","dina@","1234",new ArrayList<>()));
            userService.saveuser(new User(null,"soso","soso@","1234",new ArrayList<>()));
            userService.saveuser(new User(null,"yoyo","yoyo@","1234",new ArrayList<>()));

            userService.addRoleToUser("ahmed@","ROLE_MANAGER");
//            userService.addRoleToUser("ahmed@","ROLE_USER");
            userService.addRoleToUser("ahmed@","ROLE_ADMIN");
            userService.addRoleToUser("dina@","ROLE_USER");
            userService.addRoleToUser("soso@","ROLE_ADMIN");
            userService.addRoleToUser("yoyo@","ROLE_SUPER_ADMIN");
        };
    }
}
