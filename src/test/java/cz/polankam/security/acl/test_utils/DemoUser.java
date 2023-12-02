package cz.polankam.security.acl.test_utils;

import cz.polankam.security.acl.Authorized;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;

/**
 * Demo user entity.
 */
public class DemoUser implements Authorized {

    private String username;
    private String role;

    public DemoUser(String username, String role) {
        this.username = username;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(role));
    }
}
