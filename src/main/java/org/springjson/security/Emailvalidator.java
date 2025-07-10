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
    public boolean test(String email) {
        boolean user = userRepo.existsByEmail(email);
        return email != null && email.matches(EMAIL_REGEX) && !user;
    }

    public boolean test1(String email) {
        User user = userRepo.findByEmail(email);
        return email != null && user == null;
    }


}
