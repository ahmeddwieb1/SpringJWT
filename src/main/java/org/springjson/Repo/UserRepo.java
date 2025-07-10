package org.springjson.Repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springjson.domain.User;

public interface UserRepo extends JpaRepository<User,Long> {

    boolean existsByEmail(String email);
    User findByEmail(String email);
}
