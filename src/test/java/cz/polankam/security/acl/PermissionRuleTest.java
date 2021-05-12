package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionRuleTest {

    @Test
    void testSingleAction() {
        PermissionCondition<Object> condition = (user, resource) -> true;
        PermissionRule rule = new PermissionRule(true, "resource", "action", condition);

        assertTrue(rule.isAllowed());
        assertEquals("resource", rule.getResource());
        assertEquals(1, rule.getActions().size());
        assertEquals("action", rule.getActions().get(0));
        assertEquals(condition, rule.getCondition());
    }

    @Test
    void testMultipleActions() {
        PermissionCondition<Object> condition = (user, resource) -> true;
        PermissionRule rule = new PermissionRule(true,
                "resource", Arrays.asList("action1", "action2"), condition);

        assertTrue(rule.isAllowed());
        assertEquals("resource", rule.getResource());
        assertEquals(2, rule.getActions().size());
        assertEquals("action1", rule.getActions().get(0));
        assertEquals("action2", rule.getActions().get(1));
        assertEquals(condition, rule.getCondition());
    }
}