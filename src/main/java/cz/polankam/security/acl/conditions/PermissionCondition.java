package cz.polankam.security.acl.conditions;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * Functional interface for permission conditions. Main test method is used for
 * evaluation of condition with given user and resource.
 * @param <T> type of resource given in testing method
 *
 * Created by Martin Polanka
 */
@FunctionalInterface
public interface PermissionCondition<T> {

    /**
     * Test method which evaluates condition against given user and resource.
     * @param user user against which condition is evaluated
     * @param resource resource against which condition is evaluated
     * @return true if condition is truthy, false otherwise
     */
    boolean test(UserDetails user, T resource);
}
