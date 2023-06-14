package ru.kata.spring.boot_security.demo.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.model.User;

import java.util.List;

public interface UserService extends UserDetailsService {

    void addUser(User user);

    void deleteUser(Long id);

    void updateUser(User user);

    List<User> getAllUsers();

    User getUserById(Long id);

    User findByUsername(String username);

}
