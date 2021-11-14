package ru.pobeda.springsecurityhw.auth;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectUserFromDbByUserName(String username);
}
