package cz.polankam.security.acl.test_utils;

/**
 * Demo group entity.
 */
public class DemoGroup {

    public boolean isMember(DemoUser user) {
        return true;
    }

    public boolean isManager(DemoUser user) {
        return user.getUsername().equals("manager");
    }
}
