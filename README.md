# JACLP: Java ACL Permissions library

[![Build Status](https://travis-ci.org/Neloop/jaclp.svg?branch=master)](https://travis-ci.org/Neloop/jaclp)
[![License](http://img.shields.io/:license-mit-blue.svg)](https://github.com/Neloop/jaclp/blob/master/LICENSE)

**JACLP: ACL Permission library for Spring Security** introduces static _ACL-based_ role permission system with a touch of _ABAC_ (Attribute-based access control) over resources. It is integrated within Spring Security and its expression based permission control which might be used from `Authorize`-like annotations over endpoints or generally methods.

## Installation

Installation of the library is possible through maven dependencies and only from kraken environment:

```xml
<dependency>
    <groupId>cz.polankam.security.acl</groupId>
    <artifactId>jaclp</artifactId>
    <version>!!VERSION!!</version>
</dependency>
```

## Example Usage

The main thing in usage of `jaclp` library is definition of permission itself. There are two ways how to do this, either using role-based _ACL_, or _ABAC_ authorization. Role-based _ACL_ defines if action is allowed on resource or not. _ABAC_ in this implementation is created on top of ACL and adds condition to the authorization. Condition is resource-specific action which has to be checked against particular resource object obtained from resource repository. Examples of simple and complex usage of _ACL_ and _ABAC_ condition follows.

**Define role-based ACL permissions:**

```java
Role user = new Role("user");
user.addPermissionRules(
    true,
    "group",
    "viewAll"
);

```

**Define simple ABAC permissions on resource:**

```java
Role user = new Role("user");
user.addPermissionRules(
    true,
    "group",
    new String[] {"viewDetail"},
    (user, group) -> group.isPublic()
);

```

**Define complex ABAC permissions on resource:**

```java
Role user = new Role("user");
user.addPermissionRules(
    true,
    "group",
    new String[] {"viewStats"},
    ConditionsFactory::and(
        (user, group) -> group.isPublic(),
        ConditionsFactory::or(
            GroupConditions::isVisibleFromNow(user, group),
            GroupConditions::isSuperGlobal(user, group)
        )
    )
);
```

The things above are related to specifying permissions, the last thing is, we need to use the permissions. The permissions are used whenever Spring Security permission expression `hasPermission` is called. Therefore we can use this library in `Authorize` annotations which ideally would be located on all public endpoints.

**Sample GET group endpoints:**

```java
@GetMapping("groups")
@PreAuthorize("hasPermission('group', 'viewAll')")
public List<GroupDTO> getCurrentUser() {
    List<GroupDTO> groups = this.groupService.findAllGroups();
    return groups;
}

@GetMapping("groups/{id}")
@PreAuthorize("hasPermission(#id, 'group', 'viewDetail')")
public GroupDetailDTO getGroupDetail(@PathVariable long id) {
    GroupDetailDTO group = this.groupService.getGroupDetail(id);
    return group;
}
```

## Integration

There are two steps which needs to be done after installing `jaclp` dependency. Former is implement permissions configuration, latter defining `PermissionService`. Configuration is used for defining permission expression evaluator and integrate it in your project. Permission service should implement `IPermissionService` interface and define all user roles and their permissions within your project.

### Permission Configuration Example

```java
package app.config;

import cz.polankam.security.acl.AclPermissionEvaluator;
import cz.polankam.security.acl.AuthorizatorService;
import cz.polankam.security.acl.IPermissionsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

/**
 * Enable and set method security, most importantly define custom behavior for
 * <code>hasPermission</code> authorization methods within authorize
 * annotations.
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

    private AclPermissionEvaluator permissionEvaluator;

    @Autowired
    public MethodSecurityConfig(IPermissionsService permissionsService) {
        permissionEvaluator = new AclPermissionEvaluator(permissionsService);
    }


    @Bean
    public AuthorizatorService authorizatorService() {
        return new AuthorizatorService(permissionEvaluator);
    }

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        // set custom permission evaluator for hasPermission expressions
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }
}

```

### Permission Service Example

Following implementation is only example and it should be different for every project. The important thing is to implement `getRole()` and `getResource()` methods to comply `IPermissionService` interface. Get role method should return `Role` object which contains defined permission rules for the given role identification. Get resource method is used for _ABAC_ authorization and should return resource repository for given resource identification. If project does not use _ABAC_ authorization `getResource()` can return empty list.

```java
package app.security.acl;

import app.repositories.FileRepository;
import app.repositories.GroupRepository;
import app.security.acl.conditions.GroupConditions;
import cz.polankam.security.acl.IPermissionsService;
import cz.polankam.security.acl.IResourceRepository;
import cz.polankam.security.acl.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class PermissionsService implements IPermissionsService {

    private Map<String, Role> roles = new HashMap<>();
    private Map<String, IResourceRepository> resources = new HashMap<>();

    /**
     * Default constructor which initialize all user roles used within
     * application and assign permission rules to them.
     * @param groupRepository
     * @param fileRepository
     */
    @Autowired
    public PermissionsService(
            GroupRepository groupRepository,
            FileRepository fileRepository
    ) {
        Role user = new Role(Roles.USER);
        Role admin = new Role(Roles.ADMINISTRATOR, user);

        user.addPermissionRules(
                true,
                "group",
                new String[] {"view"},
                GroupConditions::isMember
        ).addPermissionRules(
                true,
                "group",
                new String[] {"update"},
                GroupConditions::isManager
        );

        admin.addPermissionRules(
                true,
                "group",
                "create"
        );

        roles.put(user.getName(), user);
        roles.put(admin.getName(), admin);

        // repositories which will be used to find resources by identification
        resources.put("group", groupRepository);
        resources.put("file", fileRepository);
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
```
