package ru.pobeda.springsecurityhw.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.pobeda.springsecurityhw.auth.ApplicationUserService;
import ru.pobeda.springsecurityhw.jwt.JwtProvider;
import ru.pobeda.springsecurityhw.jwt.JwtTokenVerifierFilter;
import ru.pobeda.springsecurityhw.jwt.JwtUsernameAndPasswordAuthenticationFilter;


@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtProvider jwtProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtProvider))
                .addFilterAfter(new JwtTokenVerifierFilter(jwtProvider), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index").permitAll()
//                .antMatchers("/manger/api/**").hasRole(MANAGER.name())
//                .antMatchers(HttpMethod.PUT, "/api/task").hasAuthority(TASK_WRITE.getPermission())
//                .antMatchers("/api/task/**").hasAnyRole(EMPLOYEE.name(), TRAINEE.name())
                .anyRequest()
                .authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());

    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }




//    @Bean
//    @Override
//    protected UserDetailsService userDetailsService() {
//        UserDetails oliverUser = User.builder()
//                .username("oliver")
//                .password(passwordEncoder.encode("password"))
//                .authorities(EMPLOYEE.getAuthorities())
//                .build();
//
//        UserDetails henryUser = User.builder()
//                .username("henry")
//                .password(passwordEncoder.encode("password123"))
//                .authorities(MANAGER.getAuthorities())
//                .build();
//
//        UserDetails emmaUser = User.builder()
//                .username("emma")
//                .password(passwordEncoder.encode("password"))
//                .authorities(TRAINEE.getAuthorities())
//                .build();
//        return new InMemoryUserDetailsManager(oliverUser, henryUser, emmaUser);
//    }
}
