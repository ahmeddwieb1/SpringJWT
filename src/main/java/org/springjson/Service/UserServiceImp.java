package org.springjson.Service;

import lombok.AllArgsConstructor;
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
import org.springjson.security.Emailvalidator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
//@AllArgsConstructor
@Slf4j
public class UserServiceImp implements UserService, UserDetailsService {

    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepo roleRepo;
    private final Emailvalidator emailvalidator;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        //TODO:
        User user = userRepo.findByEmail(email);
        if (user == null) {
            log.error("User not found with email: {}", email);
            throw new UsernameNotFoundException("User not found with email: " + email);
        } else {
            log.info("User found with email: {}", email);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role ->
                authorities.add(new SimpleGrantedAuthority(role.getName())));
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), authorities);
    }

    //TODO:we can edit this method tho be came option<User>
    @Override
    public User saveuser(User user) {
        boolean isemailvalid = emailvalidator.test(user.getEmail());
        //DONE:make it work
        if (isemailvalid) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            log.info("saving new user to database");
            return userRepo.save(user);
        }
        return null;
    }

    @Override
    public Role saveRole(Role role) {
        log.info("saving new role to database");
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String email, String roleName) {
        log.info("adding role {} to user {}", roleName, email);
        User user = userRepo.findByEmail(email);
        boolean isvalid = userRepo.existsByEmail(email);
        Role role = roleRepo.findByName(roleName);
        boolean isrole = roleRepo.existsByName(roleName);
        if (user != null && role != null && isvalid && isrole) {
            user.getRoles().add(role);
        }
        log.info("added");
    }
    @Override
    public User getUser(String email) {
        if (email == null) {
            log.error("email is null");
        }
        log.info("getting user {}", email);
        return userRepo.findByEmail(email);
    }

    @Override
    public List<User> getUsers() {
        log.info("getting all users");
        return userRepo.findAll();
    }

    @Override
    public List<Role> getRoles() {
        log.info("getting all roles");
        var roles = roleRepo.findAll();
        log.info("role {}", roles);
        return roles;
    }

    @Override
    public void deleteuser(String email) {
        User user = userRepo.findByEmail(email);
        if (user != null) {
            userRepo.delete(user);
        } else {
            throw new UsernameNotFoundException("user not found " + email);
        }
    }
}
