package cz.polankam.security.acl.conditions;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TrueConditionTest {

    @Test
    void test_Correct() {
        TrueCondition<String> condition = new TrueCondition<>();
        assertTrue(condition.test(null, null));
    }
}