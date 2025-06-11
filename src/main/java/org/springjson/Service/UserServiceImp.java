package org.springjson.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springjson.Repo.RoleRepo;
import org.springjson.Repo.UserRepo;
import org.springjson.domain.Role;
import org.springjson.domain.User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImp implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepo roleRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.findByusername(username);
        if (user == null) {
            log.error("User not found with username: {}", username);
            throw new UsernameNotFoundException("User not found with username: " + username);
        } else {
            log.info("User found with username: {}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role ->
                authorities.add(new SimpleGrantedAuthority(role.getName())));
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public User saveuser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        log.info("saving new user to database");
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role to database");
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("adding role {} to user{}", roleName, username);
        User user = userRepo.findByusername(username);
        Role role = roleRepo.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("getting user {}", username);
        return userRepo.findByusername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("getting all users");
        return userRepo.findAll();
    }
}
