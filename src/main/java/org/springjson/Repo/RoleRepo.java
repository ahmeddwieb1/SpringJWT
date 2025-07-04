package org.springjson.Repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springjson.domain.Role;

public interface RoleRepo extends JpaRepository<Role,Long> {
    Role findByName(String name);
    boolean existsByName(String name);
}
