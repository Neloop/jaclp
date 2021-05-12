package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RoleTest {

    @Test
    void getNameAndParent() {
        Role parent = new Role("parent_role_name");
        Role role = new Role("role_name", parent);

        assertEquals("role_name", role.getName());
        assertEquals(parent, role.getParent());
        assertNull(parent.getParent());
    }

    @Test
    void addPermissionRules() {
        Role role = new Role("role");
        role.addPermissionRules(true, "res1", new String[]{"action1", "action2"});
        role.addPermissionRules(false, "res2", new String[]{"action3"});

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
        PermissionCondition<Object> condition1 = (user, condition) -> true;
        PermissionCondition<Object> condition2 = (user, condition) -> false;

        Role role = new Role("role");
        role.addPermissionRules(true, "res1", new String[]{"action1", "action2"}, condition1);
        role.addPermissionRules(false, "res2", new String[]{"action3"}, condition2);

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
    void addPermissionRulesConditionVarargs() {
        PermissionCondition<Object> condition1 = (user, condition) -> true;
        PermissionCondition<Object> condition2 = (user, condition) -> false;

        Role role = new Role("role");
        role.addPermissionRules(true, "res1", condition1, "action1", "action2");
        role.addPermissionRules(false, "res2", condition2, "action3");

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
        Role parent = new Role("parent");
        parent.addPermissionRules(false, "res2", new String[]{"action3"});

        Role role = new Role("role", parent);
        role.addPermissionRules(true, "res1", new String[]{"action1", "action2"});

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
        Role role = new Role("role");
        role.addPermissionRules(true, "res1", new String[]{"action1", "action2"});
        role.addPermissionRules(false, "res2", new String[]{"action3"});

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
        Role parent = new Role("parent");
        parent.addPermissionRules(false, "res2", new String[]{"action3"});

        Role role = new Role("role", parent);
        role.addPermissionRules(true, "res1", new String[]{"action1", "action2"});

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