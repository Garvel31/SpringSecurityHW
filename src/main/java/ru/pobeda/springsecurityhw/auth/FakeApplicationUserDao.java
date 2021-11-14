package ru.pobeda.springsecurityhw.auth;

import com.google.common.collect.Lists;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

import static ru.pobeda.springsecurityhw.config.ApplicationUserRole.*;

@RequiredArgsConstructor
@Service("fake")
public class FakeApplicationUserDao implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Override
    public Optional<ApplicationUser> selectUserFromDbByUserName(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }


    private List<ApplicationUser> getApplicationUsers() {
        return Lists.newArrayList(
                new ApplicationUser(
                        "oliver",
                        passwordEncoder.encode("password"),
                        EMPLOYEE.getAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "henry",
                        passwordEncoder.encode("password"),
                        MANAGER.getAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        "emma",
                        passwordEncoder.encode("password"),
                        TRAINEE.getAuthorities(),
                        true,
                        true,
                        true,
                        true
                ),

                new ApplicationUser(
                        "alex",
                        passwordEncoder.encode("password"),
                        SCRUM_MASTER.getAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
    }

}
