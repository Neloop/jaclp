package cz.polankam.security.acl;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;

/**
 * Authorizator service, which can be used within whole application for custom
 * authorization checks. Internally it uses custom defined permission evaluator
 * based on user roles and acl permission rules.
 *
 * Created by Martin Polanka
 */
public class AuthorizatorService {

    /** Evaluates all permission related requests */
    private final AclPermissionEvaluator permissionEvaluator;

    /**
     * Constructor.
     * @param permissionEvaluator evaluator
     */
    public AuthorizatorService(AclPermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }


    /**
     * For the given resource and action determine if currently logged user is
     * allowed to perform the action.
     * @param resource resource which user wants to access
     * @param action action which user wants to take
     * @return true if the actions is allowed on given resource, false otherwise
     */
    public boolean isAllowed(String resource, String action) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return permissionEvaluator.hasPermission(authentication, resource, action);
    }

    /**
     * For the given resource, its identification and action determine if
     * currently logged user is allowed to perform the action.
     * @param resource resource which user wants to access
     * @param resourceId identification of the resource
     * @param action action which user wants to take
     * @return true if the actions is allowed on given resource, false otherwise
     */
    public boolean isAllowed(String resource, Serializable resourceId, String action) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return permissionEvaluator.hasPermission(authentication, resourceId, resource, action);
    }
}
