package cz.polankam.security.acl;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Interface for marking an entity that may have authority.
 * <p>
 * Created by Alexander Tsapyrin
 */
public interface Authorized {
    Collection<? extends GrantedAuthority> getAuthorities();
}
