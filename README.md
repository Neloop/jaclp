# JACLP: Java ACL Permissions library

[![Build Status](https://github.com/Neloop/jaclp/workflows/CI/badge.svg)](https://github.com/Neloop/jaclp/actions)
[![License](http://img.shields.io/:license-mit-blue.svg)](https://github.com/Neloop/jaclp/blob/master/LICENSE)
[![Maven Central Release](https://img.shields.io/maven-central/v/cz.polankam.security.acl/jaclp?color=orange)](https://mvnrepository.com/artifact/cz.polankam.security.acl/jaclp)
[![GitHub Release](https://img.shields.io/github/release/neloop/jaclp.svg)](https://github.com/Neloop/jaclp/releases)

**JACLP: ACL Permission library for Spring Security** introduces static 
_ACL-based_ role permission system with a touch of _ABAC_ (Attribute-based 
access control) over resources. It is integrated within Spring Security and its 
expression based permission control which might be used from `Authorize`-like 
annotations over endpoints or generally methods in services.

## Installation

Installation of the library is possible through maven dependencies, it is hosted
on [Maven Central](https://mvnrepository.com/artifact/cz.polankam.security.acl/jaclp).
Be sure to fill in the latest version:

```xml
<dependency>
    <groupId>cz.polankam.security.acl</groupId>
    <artifactId>jaclp</artifactId>
    <version>!!VERSION!!</version>
</dependency>
```

## Example Usage

With `jaclp` library you can define roles with _ACL_ permissions or _ABAC_ 
authorization. Role-based _ACL_ defines if action is allowed on resource or not.
_ABAC_ in this implementation is created on top of ACL and adds condition to the
authorization. Condition is resource-specific action which has to be checked
against particular resource object obtained from resource repository. Examples
of simple and complex definition of _ACL_ and _ABAC_ permissions follows.

**Define role-based ACL permissions:**

```java
Role userRole = RoleBuilder.create("user")
        .addAllowedRule("group", "viewAll")
        .build();
```

**Define simple ABAC permissions on resource:**

```java
Role userRole = RoleBuilder.create("user")
        .addAllowedRule("group",
                (UserDetails user, GroupEntity group) -> group.isPublic(), 
                "viewDetail")
        .build();
```

**Define permissions with wildcards:**

There is one defined wildcard, the asterisk, it can be used as a resource or as 
an action. If asterisk is used all resources or actions used in `hasPermission` 
calls are matched against specified permission.

```java
Role superadminRole = RoleBuilder.create("superadmin")
        .addAllowedRule("*", "*")
        .build();
```

**Define complex ABAC permissions on resource:**

```java
Role userRole = RoleBuilder.create("user")
        .addAllowedRule("group")
            .addAction("viewStats")
            .condition(ConditionsFactory.and(
                    (UserDetails user, GroupEntity group) -> group.isPublic(),
                    ConditionsFactory.or(
                            GroupConditions::isVisibleFromNow,
                            GroupConditions::isSuperGlobal
                    )
            ))
            .endRule()
        .build();
```

After you defined roles used within your application, the next this is to use
them to actually protect some endpoints or internal APIs. After successful
[integration](#integration-into-spring-application) of `jaclp` library to Spring
application, permissions are used whenever Spring Security permission expression
`hasPermission` is called. Therefore we can use permissions in `Authorize`
annotations, these annotations should be preferably placed on public endpoints
of your application.

**Sample GET endpoints using permission evaluation:**

```java
@GetMapping("groups")
@PreAuthorize("hasPermission('group', 'viewAll')")
public List<GroupDTO> getCurrentUser() {
    return this.groupService.findAllGroups();
}

@GetMapping("groups/{id}")
@PreAuthorize("hasPermission(#id, 'group', 'viewDetail')")
public GroupDetailDTO getGroupDetail(@PathVariable long id) {
    return this.groupService.getGroupDetail(id);
}
```

## Example Project

There is example project which demonstrates usage and integration of JACLP into
the Spring Boot, Spring Data JPA and Spring Security stack. This example is
located in separated repository [jaclp-demo](https://github.com/Neloop/jaclp-demo).

## Integration into Spring Application

There are two steps which needs to be done after installing `jaclp` dependency.
Former is ideally import pre-defined permissions configuration, latter defining
`PermissionService`. Configuration is used for creating permission expression
evaluator and integrate it in your project. Permission service on the other hand
should implement `IPermissionService` interface and define all user roles and
their permissions within your project.

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
@Import(JaclpSpringConfiguration.class)
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

    private final AclPermissionEvaluator permissionEvaluator;

    /**
     * Note: @Lazy annotation is very important here, it protects evaluator and
     * potential autowired classes from not being able to be processed by
     * BeanPostProcessor, which handles for example Spring AOP.
     */
    @Autowired
    public MethodSecurityConfig(@Lazy AclPermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
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

Following implementation is only example and it should be different for every 
project. The important thing is to implement `getRole()` and `getResource()` 
methods to comply with `IPermissionService` interface. Get role method should 
return  `Role` object which contains defined permission rules for the given role 
identification. Get resource method is used for _ABAC_ authorization and should 
return resource repository for given resource identification. If project does 
not use _ABAC_ authorization `getResource()` can return empty list.

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
