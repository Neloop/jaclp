package cz.polankam.security.acl;

import cz.polankam.security.acl.conditions.PermissionCondition;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionRuleTest {

    @Test
    void test() {
        PermissionCondition condition = (user, resource) -> true;
        PermissionRule rule = new PermissionRule(true, "resource", "action", condition);

        assertTrue(rule.isAllowed());
        assertEquals("resource", rule.getResource());
        assertEquals("action", rule.getAction());
        assertEquals(condition, rule.getCondition());
    }
}