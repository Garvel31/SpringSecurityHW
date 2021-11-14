package ru.pobeda.springsecurityhw.config;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static ru.pobeda.springsecurityhw.config.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    EMPLOYEE(Sets.newHashSet(EMPLOYEE_READ, TASK_READ, TASK_WRITE)),
    MANAGER(Sets.newHashSet(EMPLOYEE_READ, EMPLOYEE_WRITE, TASK_READ, TASK_WRITE)),
    TRAINEE(Sets.newHashSet(TASK_READ, EMPLOYEE_READ)),
    SCRUM_MASTER(Sets.newHashSet(TASK_WRITE, EMPLOYEE_READ));

    private final Set<ru.pobeda.springsecurityhw.config.ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ru.pobeda.springsecurityhw.config.ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ru.pobeda.springsecurityhw.config.ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getAuthorities() {
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
