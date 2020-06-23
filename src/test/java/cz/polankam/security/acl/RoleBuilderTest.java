package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RoleBuilderTest {

    @Test
    void getNameAndParent() {
        Role parent = RoleBuilder.create("parent_role_name").build();
        Role role = RoleBuilder.create("role_name").parent(parent).build();

        assertEquals("role_name", role.getName());
        assertEquals(parent, role.getParent());
        assertNull(parent.getParent());
    }

    @Test
    void addPermissionRules() {
        Role role = RoleBuilder.create("role")
                .addAllowedRule("res1", "action1", "action2")
                .addDeniedRule("res2", "action3")
                .build();

        List<PermissionRule> rules = role.getPermissionRules();
        assertEquals(2, rules.size());

        PermissionRule rule1 = rules.get(0);
        assertTrue(rule1.isAllowed());
        assertEquals("res1", rule1.getResource());
        assertEquals(2, rule1.getActions().size());
        assertEquals("action1", rule1.getActions().get(0));
        assertEquals("action2", rule1.getActions().get(1));

        PermissionRule rule2 = rules.get(1);
        assertFalse(rule2.isAllowed());
        assertEquals("res2", rule2.getResource());
        assertEquals(1, rule2.getActions().size());
        assertEquals("action3", rule2.getActions().get(0));
    }

    @Test
    void addRulesWithPermissionBuilder() {
        Role role = RoleBuilder.create("role")
                .addAllowedRule("res1")
                    .addAction("action1")
                    .addActions("action2")
                    .endRule()
                .addDeniedRule("res2")
                    .addAction("action3")
                    .endRule()
                .build();

        List<PermissionRule> rules = role.getPermissionRules();
        assertEquals(2, rules.size());

        PermissionRule rule1 = rules.get(0);
        assertTrue(rule1.isAllowed());
        assertEquals("res1", rule1.getResource());
        assertEquals(2, rule1.getActions().size());
        assertEquals("action1", rule1.getActions().get(0));
        assertEquals("action2", rule1.getActions().get(1));

        PermissionRule rule2 = rules.get(1);
        assertFalse(rule2.isAllowed());
        assertEquals("res2", rule2.getResource());
        assertEquals(1, rule2.getActions().size());
        assertEquals("action3", rule2.getActions().get(0));
    }

    @Test
    void addPermissionRulesCondition() {
        PermissionCondition condition1 = (user, condition) -> true;
        PermissionCondition condition2 = (user, condition) -> false;

        Role role = RoleBuilder.create("role")
                .addAllowedRule("res1", condition1, "action1", "action2")
                .addDeniedRule("res2", condition2, "action3")
                .build();

        List<PermissionRule> rules = role.getPermissionRules();
        assertEquals(2, rules.size());

        PermissionRule rule1 = rules.get(0);
        assertTrue(rule1.isAllowed());
        assertEquals("res1", rule1.getResource());
        assertEquals(2, rule1.getActions().size());
        assertEquals("action1", rule1.getActions().get(0));
        assertEquals("action2", rule1.getActions().get(1));
        assertEquals(condition1, rule1.getCondition());

        PermissionRule rule2 = rules.get(1);
        assertFalse(rule2.isAllowed());
        assertEquals("res2", rule2.getResource());
        assertEquals(1, rule2.getActions().size());
        assertEquals("action3", rule2.getActions().get(0));
        assertEquals(condition2, rule2.getCondition());
    }

    @Test
    void addRulesConditionWithPermissionBuilder() {
        PermissionCondition condition1 = (user, condition) -> true;
        PermissionCondition condition2 = (user, condition) -> false;

        Role role = RoleBuilder.create("role")
                .addAllowedRule("res1")
                    .condition(condition1)
                    .addAction("action1")
                    .addActions(Arrays.asList("action2"))
                    .endRule()
                .addDeniedRule("res2")
                    .condition(condition2)
                    .addAction("action3")
                    .endRule()
                .build();

        List<PermissionRule> rules = role.getPermissionRules();
        assertEquals(2, rules.size());

        PermissionRule rule1 = rules.get(0);
        assertTrue(rule1.isAllowed());
        assertEquals("res1", rule1.getResource());
        assertEquals(2, rule1.getActions().size());
        assertEquals("action1", rule1.getActions().get(0));
        assertEquals("action2", rule1.getActions().get(1));
        assertEquals(condition1, rule1.getCondition());

        PermissionRule rule2 = rules.get(1);
        assertFalse(rule2.isAllowed());
        assertEquals("res2", rule2.getResource());
        assertEquals(1, rule2.getActions().size());
        assertEquals("action3", rule2.getActions().get(0));
        assertEquals(condition2, rule2.getCondition());
    }

    @Test
    void getPermissionRulesFromParent() {
        Role parent = RoleBuilder.create("parent")
                .addDeniedRule("res2", "action3")
                .build();

        Role role = RoleBuilder.create("role")
                .parent(parent)
                .addAllowedRule("res1", "action1", "action2")
                .build();

        List<PermissionRule> rules = role.getPermissionRules();
        assertEquals(2, rules.size());

        PermissionRule rule1 = rules.get(0);
        assertTrue(rule1.isAllowed());
        assertEquals("res1", rule1.getResource());
        assertEquals(2, rule1.getActions().size());
        assertEquals("action1", rule1.getActions().get(0));
        assertEquals("action2", rule1.getActions().get(1));

        PermissionRule rule2 = rules.get(1);
        assertFalse(rule2.isAllowed());
        assertEquals("res2", rule2.getResource());
        assertEquals(1, rule2.getActions().size());
        assertEquals("action3", rule2.getActions().get(0));
    }

    @Test
    void getPermissionRulesByResource() {
        Role role = RoleBuilder.create("role")
                .addAllowedRule("res1", "action1", "action2")
                .addDeniedRule("res2", "action3")
                .build();

        List<PermissionRule> res1Rules = role.getPermissionRules("res1");
        assertEquals(1, res1Rules.size());

        PermissionRule rule1 = res1Rules.get(0);
        assertTrue(rule1.isAllowed());
        assertEquals("res1", rule1.getResource());
        assertEquals(2, rule1.getActions().size());
        assertEquals("action1", rule1.getActions().get(0));
        assertEquals("action2", rule1.getActions().get(1));

        List<PermissionRule> res2Rules = role.getPermissionRules("res2");
        assertEquals(1, res2Rules.size());

        PermissionRule rule2 = res2Rules.get(0);
        assertFalse(rule2.isAllowed());
        assertEquals("res2", rule2.getResource());
        assertEquals(1, rule2.getActions().size());
        assertEquals("action3", rule2.getActions().get(0));
    }

    @Test
    void getPermissionRulesByResourceFromParent() {
        Role parent = RoleBuilder.create("parent")
                .addDeniedRule("res2", "action3")
                .build();

        Role role = RoleBuilder.create("role")
                .parent(parent)
                .addAllowedRule("res1", "action1", "action2")
                .build();

        List<PermissionRule> res1Rules = role.getPermissionRules("res1");
        assertEquals(1, res1Rules.size());

        PermissionRule rule1 = res1Rules.get(0);
        assertTrue(rule1.isAllowed());
        assertEquals("res1", rule1.getResource());
        assertEquals(2, rule1.getActions().size());
        assertEquals("action1", rule1.getActions().get(0));
        assertEquals("action2", rule1.getActions().get(1));

        List<PermissionRule> res2Rules = role.getPermissionRules("res2");
        assertEquals(1, res2Rules.size());

        PermissionRule rule2 = res2Rules.get(0);
        assertFalse(rule2.isAllowed());
        assertEquals("res2", rule2.getResource());
        assertEquals(1, rule2.getActions().size());
        assertEquals("action3", rule2.getActions().get(0));
    }
}