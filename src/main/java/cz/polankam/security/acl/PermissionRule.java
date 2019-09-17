package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;

/**
 * Permission rule which should be applied for the given resource and action on
 * this resource. The resulting allowance is determined on the isAllowed flag,
 * therefore the rule can be either positive or negative.
 *
 * Created by Martin Polanka
 */
public class PermissionRule {

    /** Is this rule allowing access or not allowing */
    private boolean isAllowed;
    /** Textual representation of resource of this rule */
    private String resource;
    /** Action which this rule allows or not */
    private String action;
    /** Condition applied to resource object, might be null */
    private PermissionCondition condition;

    /**
     * Construct permission rule with given parameters.
     * @param isAllowed if the action on the resource is allowed or not
     * @param resource resource for which the rule should be applied
     * @param action action for which the rule should be applied
     * @param condition condition applied to resource object, might be null
     */
    public PermissionRule(boolean isAllowed, String resource, String action, PermissionCondition condition) {
        this.isAllowed = isAllowed;
        this.resource = resource;
        this.action = action;
        this.condition = condition;
    }


    /**
     * Determines if the rule on the resource and action is allowed or not.
     * @return true if allowed, false otherwise
     */
    public boolean isAllowed() {
        return isAllowed;
    }

    /**
     * Get the resource associated with this permission rule.
     * @return textual representation of resource
     */
    public String getResource() {
        return resource;
    }

    /**
     * Get the action associated with this permission rule.
     * @return textual representation of action
     */
    public String getAction() {
        return action;
    }

    /**
     * Condition applied to resource object, might be null if resource
     * identification is out of scope of the permission.
     * @return condition functional interface
     */
    public PermissionCondition getCondition() {
        return condition;
    }
}
