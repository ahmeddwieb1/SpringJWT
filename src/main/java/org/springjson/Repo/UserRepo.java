package org.springjson.Repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springjson.domain.User;

public interface UserRepo extends JpaRepository<User,Long> {
    User findByusername(String username);

    boolean existsByUsername(String username);
}
