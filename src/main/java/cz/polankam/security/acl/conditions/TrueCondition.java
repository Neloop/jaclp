package cz.polankam.security.acl.conditions;

import cz.polankam.security.acl.Authorized;

/**
 * Condition which is always validated to true.
 * Creation is done by provided factory {@link ConditionsFactory}.
 * @param <T> type of resource given in testing method
 *
 * Created by Martin Polanka
 */
final class TrueCondition<T> implements PermissionCondition<T> {

    @Override
    public boolean test(Authorized user, T resource) {
        return true;
    }
}
