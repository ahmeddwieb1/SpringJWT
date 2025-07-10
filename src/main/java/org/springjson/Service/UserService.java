package org.springjson.Service;

import org.springjson.domain.Role;
import org.springjson.domain.User;

import java.util.List;

public interface UserService {
    User saveuser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String email,String roleName);
    User getUser(String email);
    List<User> getUsers();
    List<Role> getRoles();
    void deleteuser(String email);
}
