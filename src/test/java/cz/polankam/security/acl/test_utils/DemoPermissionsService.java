package cz.polankam.security.acl.test_utils;

import cz.polankam.security.acl.IPermissionsService;
import cz.polankam.security.acl.IResourceRepository;
import cz.polankam.security.acl.Role;
import cz.polankam.security.acl.conditions.ConditionsFactory;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashMap;
import java.util.Map;

/**
 * Demo permission service implementation.
 */
public class DemoPermissionsService implements IPermissionsService {

    private Map<String, Role> roles = new HashMap<>();
    private Map<String, IResourceRepository> resources = new HashMap<>();

    /**
     * Default constructor which initialize all user roles used within
     * application and assign permission rules to them.
     */
    public DemoPermissionsService() {
        Role user = new Role("USER");
        Role admin = new Role("ADMIN", user);

        user.addPermissionRules(
                true,
                "group",
                new String[] {"view"},
                ConditionsFactory.and(
                        ConditionsFactory.truthy(), // just to show off and condition
                        DemoGroupConditions::isMember // actual condition
                )
        ).addPermissionRules(
                true,
                "group",
                ConditionsFactory.or(
                        (UserDetails userDetails, DemoGroup group) -> false, // just to show off or condition
                        DemoGroupConditions::isManager
                ),
                "edit"
        );

        admin.addPermissionRules(
                true,
                "instance",
                "view", "edit");

        roles.put(user.getName(), user);
        roles.put(admin.getName(), admin);
        resources.put("group", new DemoGroupRepository());
    }

    public boolean roleExists(String role) {
        return roles.containsKey(role);
    }

    public Role getRole(String roleString) {
        Role role = roles.get(roleString);
        if (role == null) {
            throw new RuntimeException("Role '" + roleString + "' not found");
        }

        return role;
    }

    public IResourceRepository getResource(String resource) {
        IResourceRepository repository = resources.get(resource);
        if (repository == null) {
            throw new RuntimeException("Resource '" + resource + "' not found");
        }

        return repository;
    }
}
