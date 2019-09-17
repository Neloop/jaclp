package cz.polankam.security.acl.test_utils;

import org.springframework.security.core.userdetails.UserDetails;

public class DemoGroupConditions {

    public static boolean isMember(UserDetails userDetails, DemoGroup resource) {
        if (!(userDetails instanceof DemoUser) ||
                resource == null) {
            return false;
        }

        return resource.isMember((DemoUser) userDetails);
    }

    public static boolean isManager(UserDetails userDetails, DemoGroup resource) {
        if (!(userDetails instanceof DemoUser) ||
                resource == null) {
            return false;
        }

        return resource.isManager((DemoUser) userDetails);
    }
}
