package org.springjson.security;

import org.springframework.stereotype.Service;
import org.springjson.Repo.UserRepo;
import org.springjson.domain.User;

import java.util.function.Predicate;

@Service
public class Emailvalidator implements Predicate<String> {
    private static final String EMAIL_REGEX = "^[A-Za-z][A-Za-z0-9_.-]*@(.+)$";
    private final UserRepo userRepo;

    public Emailvalidator(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    @Override
    public boolean test(String username) {
        boolean user = userRepo.existsByUsername(username);
        return username != null && username.matches(EMAIL_REGEX) && !user;
    }

    public boolean test1(String username) {
        User user = userRepo.findByusername(username);
        return username != null && user == null;
    }


}
