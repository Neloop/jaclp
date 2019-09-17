package cz.polankam.security.acl.conditions;

/**
 * Public factory for common permission conditions.
 *
 * Created by Martin Polanka
 */
public class ConditionsFactory {

    /**
     * Create and return Or condition which will evaluate given conditions.
     * @param conditions conditions which will be evaluated by And condition
     * @param <T> type of resource given in testing method
     * @return created or condition
     */
    @SafeVarargs
    public static <T> PermissionCondition<T> or(PermissionCondition<T>... conditions) {
        return new OrCondition<T>(conditions);
    }

    /**
     * Create and return And condition which will evaluate given conditions.
     * @param conditions conditions which will be evaluated by Or condition
     * @param <T> type of resource given in testing method
     * @return created and condition
     */
    @SafeVarargs
    public static <T> PermissionCondition<T> and(PermissionCondition<T>... conditions) {
        return new AndCondition<T>(conditions);
    }

    /**
     * Factory method for condition which is always evaluated to true.
     * @param <T> type of resource given in testing method
     * @return created condition
     */
    public static <T> PermissionCondition<T> truthy() {
        return new TrueCondition<T>();
    }
}
