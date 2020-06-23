package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;

import java.util.*;

/**
 * Representation of the role which contains its name and permission rules which
 * should be applied for the role.
 * <p>
 * Created by Martin Polanka
 */
public final class Role {

    /**
     * Name of the role
     */
    private String name;
    /**
     * Parent of this role or null
     */
    private Role parent;
    /**
     * Associative array of permission rules indexed by resource textual representation
     */
    private Map<String, List<PermissionRule>> permissionRules = new HashMap<>();


    /**
     * Constructor with the role name.
     *
     * @param name role name
     */
    public Role(String name) {
        this(name, null);
    }

    /**
     * Constructor with the role name and parent.
     *
     * @param name   role name
     * @param parent parent of this role
     */
    public Role(String name, Role parent) {
        this.name = name;
        this.parent = parent;
    }


    /**
     * If given resource is not initialized in internal map of permission rules,
     * initialize it with empty list.
     *
     * @param resource to be initialized
     */
    private void initializeResource(String resource) {
        if (!permissionRules.containsKey(resource)) {
            permissionRules.put(resource, new ArrayList<>());
        }
    }

    /**
     * Get the name of the role.
     *
     * @return role identifier
     */
    public String getName() {
        return name;
    }

    /**
     * Get parent of this role, can be null.
     *
     * @return parent role
     */
    public Role getParent() {
        return parent;
    }

    /**
     * Add given permission rules structures to this role.
     *
     * @param rules array of rules
     * @return this
     */
    public Role addPermissionRules(PermissionRule... rules) {
        for (PermissionRule rule : rules) {
            initializeResource(rule.getResource());
            permissionRules.get(rule.getResource()).add(rule);
        }
        return this;
    }

    /**
     * Add permission rules for the given resource, which is either allowed or
     * not for the given actions.
     *
     * @param isAllowed determine if the rule should be allowed for the role or not
     * @param resource  resource for which the rule should be applied
     * @param actions   actions on the resource for which the rule should be applied
     * @return this
     */
    public Role addPermissionRules(boolean isAllowed, String resource, String... actions) {
        initializeResource(resource);
        permissionRules.get(resource).add(new PermissionRule(isAllowed, resource, Arrays.asList(actions), null));
        return this;
    }

    /**
     * Add permission rules for the given resource, which is either allowed or
     * not for the given actions. Condition should be used on the acquired
     * resource object.
     *
     * @param isAllowed determine if the rule should be allowed for the user or not
     * @param resource  resource for which the rule should be applied
     * @param actions   actions on the resource for which the rule should be applied
     * @param condition condition applied to resource object
     * @return this
     */
    public <T> Role addPermissionRules(boolean isAllowed, String resource, String[] actions, PermissionCondition<T> condition) {
        initializeResource(resource);
        permissionRules.get(resource).add(new PermissionRule(isAllowed, resource, Arrays.asList(actions), condition));
        return this;
    }

    /**
     * Add permission rules for the given resource, which is either allowed or
     * not for the given actions. Condition should be used on the acquired
     * resource object.
     *
     * @param isAllowed determine if the rule should be allowed for the user or not
     * @param resource  resource for which the rule should be applied
     * @param condition condition applied to resource object
     * @param actions   actions on the resource for which the rule should be applied
     * @return this
     */
    public <T> Role addPermissionRules(boolean isAllowed, String resource, PermissionCondition<T> condition, String... actions) {
        initializeResource(resource);
        permissionRules.get(resource).add(new PermissionRule(isAllowed, resource, Arrays.asList(actions), condition));
        return this;
    }

    /**
     * Get the list of permission rules for this role and its parents.
     *
     * @return unmodifiable list of permissions
     */
    public List<PermissionRule> getPermissionRules() {
        List<PermissionRule> rules = new ArrayList<>();
        // add all permission rules from map
        permissionRules.values().forEach(rules::addAll);

        if (this.parent != null) {
            // if there is parent add also its permission rules
            rules.addAll(this.parent.getPermissionRules());
        }

        // return unmodifiable list, just to be sure
        return Collections.unmodifiableList(rules);
    }

    /**
     * Get permission rules unmodifiable list for given resource. Rules are
     * taken also from parent role of this role.
     *
     * @param resource resource for which rules are returned
     * @return unmodifiable list of permissions
     */
    public List<PermissionRule> getPermissionRules(String resource) {
        List<PermissionRule> rules = new ArrayList<>();
        if (permissionRules.containsKey(resource)) {
            // if current role contains resource, add it to resulting collection
            rules.addAll(permissionRules.get(resource));
        }

        if (this.parent != null) {
            // if there is parent add also its permission rules
            rules.addAll(this.parent.getPermissionRules(resource));
        }

        // return unmodifiable list, just to be sure
        return Collections.unmodifiableList(rules);
    }
}
