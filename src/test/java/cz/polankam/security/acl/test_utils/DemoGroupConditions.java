package cz.polankam.security.acl.test_utils;

import cz.polankam.security.acl.Authorized;

public class DemoGroupConditions {

    public static boolean isMember(Authorized user, DemoGroup resource) {
        if (!(user instanceof DemoUser) ||
                resource == null) {
            return false;
        }

        return resource.isMember((DemoUser) user);
    }

    public static boolean isManager(Authorized user, DemoGroup resource) {
        if (!(user instanceof DemoUser) ||
                resource == null) {
            return false;
        }

        return resource.isManager((DemoUser) user);
    }
}
