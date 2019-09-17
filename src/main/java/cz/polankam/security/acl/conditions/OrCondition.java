package cz.polankam.security.acl.conditions;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;

/**
 * Or condition which takes array of other conditions on construction and
 * evaluates them on logical OR operation during testing.
 * Creation is done by provided factory {@link ConditionsFactory}.
 * @param <T> type of resource given in testing method
 *
 * Created by Martin Polanka
 */
class OrCondition<T> implements PermissionCondition<T> {

    /**
     * Array of conditions which will be evaluated on testing.
     */
    private PermissionCondition<T>[] conditions;

    /**
     * Constructor.
     * @param conditions conditions which will be evaluated
     */
    @SafeVarargs
    OrCondition(PermissionCondition<T>... conditions) {
        this.conditions = conditions;
    }


    @Override
    public boolean test(UserDetails user, T resource) {
        return Arrays.stream(conditions).anyMatch(condition -> condition.test(user, resource));
    }
}
