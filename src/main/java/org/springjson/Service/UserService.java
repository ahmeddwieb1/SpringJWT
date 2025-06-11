package org.springjson.Service;

import org.springjson.domain.Role;
import org.springjson.domain.User;

import java.util.List;

public interface UserService {
    User saveuser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username,String roleName);
    User getUser(String username);
    List<User> getUsers();
}
