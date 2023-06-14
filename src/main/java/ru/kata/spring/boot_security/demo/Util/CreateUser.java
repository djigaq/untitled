package ru.kata.spring.boot_security.demo.Util;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;
import ru.kata.spring.boot_security.demo.model.Role;

import java.util.HashSet;
import java.util.Set;

@Component
public class CreateUser implements CommandLineRunner {
    private final UserService userService;
    private final RoleService roleService;

    public CreateUser(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }


    @Override
    public void run(String... args) throws Exception {
        Role roleAdmin = new Role("ROLE_ADMIN");
        Role roleUser = new Role("ROLE_USER");
        // логин = user пароль = user
        User user1 = new User("user", "surname", 25, "user@mail.ru", "user");
        // логин = admin пароль = admin
        User admin1 = new User("admin", "surname", 26, "admin@mail.ru", "admin");
        Set<Role> roleTwo = new HashSet<>();
        roleTwo.add(roleUser);
        roleTwo.add(roleAdmin);
        Set<Role> roleOne = new HashSet<>();
        roleOne.add(roleUser);
        roleService.addRole(roleUser);
        roleService.addRole(roleAdmin);
        user1.setRoles(roleOne);
        admin1.setRoles(roleTwo);
        userService.addUser(user1);
        userService.addUser(admin1);
    }
}