package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builder which can be used for convenient Role structure creation.
 * <p>
 * Created by Martin Polanka on 23.06.2020.
 */
public final class RoleBuilder {

    private String name;
    private Role parent;
    private final List<PermissionRule> rules = new ArrayList<>();

    private RoleBuilder() {
        // nothing to see here
    }

    /**
     * Create role builder for the role with specified name.
     */
    public static RoleBuilder create(String name) {
        RoleBuilder builder = new RoleBuilder();
        builder.name = name;
        return builder;
    }

    ////////////////////////////////////////////////////////////////////////////

    /**
     * Set parent of the constructed role.
     */
    public RoleBuilder parent(Role parent) {
        this.parent = parent;
        return this;
    }

    /**
     * Add allowed rule to the role and return permission rule builder.
     */
    public PermissionRuleBuilder addAllowedRule(String resource) {
        return new PermissionRuleBuilder(this, true, resource);
    }

    /**
     * Add denied rule to the role and return permission rule builder.
     */
    public PermissionRuleBuilder addDeniedRule(String resource) {
        return new PermissionRuleBuilder(this, false, resource);
    }

    /**
     * Add rule to the role and return permission rule builder.
     */
    public PermissionRuleBuilder addRule(boolean allowed, String resource) {
        return new PermissionRuleBuilder(this, allowed, resource);
    }

    /**
     * Add allowed rule to the role.
     */
    public RoleBuilder addAllowedRule(String resource, String... actions) {
        rules.add(new PermissionRule(true, resource, Arrays.asList(actions), null));
        return this;
    }

    /**
     * Add denied rule to the role.
     */
    public RoleBuilder addDeniedRule(String resource, String... actions) {
        rules.add(new PermissionRule(false, resource, Arrays.asList(actions), null));
        return this;
    }

    /**
     * Add rule to the role.
     */
    public RoleBuilder addRule(boolean allowed,
                               String resource,
                               String... actions) {
        rules.add(new PermissionRule(allowed, resource, Arrays.asList(actions), null));
        return this;
    }

    /**
     * Add allowed rule with specified condition to the role.
     */
    public <T> RoleBuilder addAllowedRule(String resource,
                                          PermissionCondition<T> condition,
                                          String... actions) {
        rules.add(new PermissionRule(true, resource, Arrays.asList(actions), condition));
        return this;
    }

    /**
     * Add denied rule with specified condition to the role.
     */
    public <T> RoleBuilder addDeniedRule(String resource,
                                         PermissionCondition<T> condition,
                                         String... actions) {
        rules.add(new PermissionRule(false, resource, Arrays.asList(actions), condition));
        return this;
    }

    /**
     * Add rule with specified condition to the role.
     */
    public <T> RoleBuilder addPermissionRule(boolean allowed,
                                             String resource,
                                             PermissionCondition<T> condition,
                                             String... actions) {
        rules.add(new PermissionRule(allowed, resource, Arrays.asList(actions), condition));
        return this;
    }

    /**
     * Build the role.
     */
    public Role build() {
        Role role = new Role(name, parent);
        role.addPermissionRules(rules);
        return role;
    }

    ////////////////////////////////////////////////////////////////////////////

    public static final class PermissionRuleBuilder {

        private final RoleBuilder roleBuilder;
        private final boolean isAllowed;
        private final String resource;
        private final List<String> actions = new ArrayList<>();
        private PermissionCondition condition;

        private PermissionRuleBuilder(RoleBuilder roleBuilder,
                                      boolean isAllowed,
                                      String resource) {
            this.roleBuilder = roleBuilder;
            this.isAllowed = isAllowed;
            this.resource = resource;
        }

        /**
         * Set specified condition to the permission rule.
         */
        public <T> PermissionRuleBuilder condition(PermissionCondition<T> condition) {
            this.condition = condition;
            return this;
        }

        /**
         * Add specified action to the permission rule.
         */
        public PermissionRuleBuilder addAction(String action) {
            actions.add(action);
            return this;
        }

        /**
         * Add specified actions to the permission rule.
         */
        public PermissionRuleBuilder addActions(String... actions) {
            this.actions.addAll(Arrays.asList(actions));
            return this;
        }

        /**
         * Add specified actions to the permission rule.
         */
        public PermissionRuleBuilder addActions(List<String> actions) {
            this.actions.addAll(actions);
            return this;
        }

        /**
         * Add permission rule to the role and continue with role building.
         */
        public RoleBuilder endRule() {
            PermissionRule rule = new PermissionRule(isAllowed, resource, actions, condition);
            roleBuilder.rules.add(rule);
            return roleBuilder;
        }
    }
}
