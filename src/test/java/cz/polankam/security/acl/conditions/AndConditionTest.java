package cz.polankam.security.acl.conditions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AndConditionTest {

    @Test
    void test_Empty() {
        AndCondition<String> condition = new AndCondition<>();
        assertTrue(condition.test(null, "resource"));
    }

    @Test
    void test_Correct() {
        PermissionCondition<String> pCondition1 = (user, res) -> res.equals("resource");
        PermissionCondition<String> pCondition2 = (user, res) -> !res.equals("resource1");
        PermissionCondition<String> pCondition3 = (user, res) -> !res.equals("res");

        AndCondition<String> condition = new AndCondition<>(pCondition1, pCondition2, pCondition3);
        assertTrue(condition.test(null, "resource"));
    }

    @Test
    void test_OneBad() {
        PermissionCondition<String> pCondition1 = (user, res) -> res.equals("resource");
        PermissionCondition<String> pCondition2 = (user, res) -> res.equals("resource1");
        PermissionCondition<String> pCondition3 = (user, res) -> !res.equals("res");

        AndCondition<String> condition = new AndCondition<>(pCondition1, pCondition2, pCondition3);
        assertFalse(condition.test(null, "resource"));
    }

    @Test
    void test_TwoBad() {
        PermissionCondition<String> pCondition1 = (user, res) -> res.equals("resource");
        PermissionCondition<String> pCondition2 = (user, res) -> res.equals("resource1");
        PermissionCondition<String> pCondition3 = (user, res) -> res.equals("res");

        AndCondition<String> condition = new AndCondition<>(pCondition1, pCondition2, pCondition3);
        assertFalse(condition.test(null, "resource"));
    }

    @Test
    void test_AllBad() {
        PermissionCondition<String> pCondition1 = (user, res) -> !res.equals("resource");
        PermissionCondition<String> pCondition2 = (user, res) -> res.equals("resource1");
        PermissionCondition<String> pCondition3 = (user, res) -> res.equals("res");

        AndCondition<String> condition = new AndCondition<>(pCondition1, pCondition2, pCondition3);
        assertFalse(condition.test(null, "resource"));
    }
}