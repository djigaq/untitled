package ru.kata.spring.boot_security.demo.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.util.HashSet;
import java.util.Set;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserService userService;
    private final SuccessUserHandler successUserHandler;

    @Autowired
    public WebSecurityConfig(@Lazy UserService userService, SuccessUserHandler successUserHandler) {
        this.userService = userService;
        this.successUserHandler = successUserHandler;
    }

    @Override
    protected void configure(HttpSecurity http)  {
        try {
            http
                    .csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/", "/welcome").permitAll()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/user/**").hasAnyRole("ADMIN", "USER")
                    .anyRequest().authenticated()
                    .and()
                    .formLogin().successHandler(successUserHandler)
                    .loginPage("/login")
                    .loginProcessingUrl("/process_login")
                    .permitAll()
                    .and()
                    .logout()
                    .permitAll();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
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
            // логин = user@email.ru пароль = user
            User user1 = new User("user", "surname", 25, "user@email.ru", "user");
            // логин = admin@email.ru пароль = admin
            User admin1 = new User("admin", "surname", 26, "admin@email.ru", "admin");
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


    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(getPasswordEncoder());
        authenticationProvider.setUserDetailsService(userService);
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}