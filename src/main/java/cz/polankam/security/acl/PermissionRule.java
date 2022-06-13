package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;

import java.util.ArrayList;
import java.util.List;

/**
 * Permission rule which should be applied for the given resource and action on
 * this resource. The resulting allowance is determined on the isAllowed flag,
 * therefore the rule can be either positive or negative.
 * <p>
 * Created by Martin Polanka
 */
public class PermissionRule {

    /**
     * Is this rule allowing access or not allowing
     */
    private final boolean isAllowed;
    /**
     * Textual representation of resource of this rule
     */
    private final String resource;
    /**
     * Actions list which this rule allows or not
     */
    private final List<String> actions;
    /**
     * Condition applied to resource object, might be null
     */
    private final PermissionCondition condition;

    /**
     * Construct permission rule with given parameters.
     *
     * @param isAllowed if the action on the resource is allowed or not
     * @param resource  resource for which the rule should be applied
     * @param action    action for which the rule should be applied
     * @param condition condition applied to resource object, might be null
     */
    public <T> PermissionRule(boolean isAllowed, String resource, String action, PermissionCondition<T> condition) {
        this.isAllowed = isAllowed;
        this.resource = resource;
        this.actions = new ArrayList<>();
        this.actions.add(action);
        this.condition = condition;
    }

    /**
     * Construct permission rule with given parameters.
     *
     * @param isAllowed if the action on the resource is allowed or not
     * @param resource  resource for which the rule should be applied
     * @param actions   list of actions for which the rule should be applied
     * @param condition condition applied to resource object, might be null
     */
    public <T> PermissionRule(boolean isAllowed, String resource, List<String> actions, PermissionCondition<T> condition) {
        this.isAllowed = isAllowed;
        this.resource = resource;
        this.actions = actions;
        this.condition = condition;
    }


    /**
     * Determines if the rule on the resource and action is allowed or not.
     *
     * @return true if allowed, false otherwise
     */
    public boolean isAllowed() {
        return isAllowed;
    }

    /**
     * Get the resource associated with this permission rule.
     *
     * @return textual representation of resource
     */
    public String getResource() {
        return resource;
    }

    /**
     * Get list of actions associated with this permission rule.
     *
     * @return textual representation of actions
     */
    public List<String> getActions() {
        return actions;
    }

    /**
     * Condition applied to resource object, might be null if resource
     * identification is out of scope of the permission.
     *
     * @return condition functional interface
     */
    public PermissionCondition<Object> getCondition() {
        return condition;
    }
}
