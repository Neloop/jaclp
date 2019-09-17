package cz.polankam.security.acl;

import cz.polankam.security.acl.exceptions.ResourceNotFoundException;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.transaction.Transactional;
import java.io.Serializable;
import java.util.Optional;

/**
 * Custom permission evaluator used for 'hasPermission' expressions within
 * authorize annotations. The implementation is based on the user roles and
 * permission rules created by the {@link IPermissionsService} which has to be
 * given at construction.
 *
 * Created by Martin Polanka
 */
@Transactional
public class AclPermissionEvaluator implements PermissionEvaluator {

    /**
     * Permission service which contains definition of roles and resource
     * repositories used for evaluation.
     */
    private IPermissionsService permissionsService;

    /**
     * Constructor.
     * @param permissionsService roles definition service
     */
    public AclPermissionEvaluator(IPermissionsService permissionsService) {
        this.permissionsService = permissionsService;
    }


    /**
     * Determine if the given user with defined roles can perform action on the
     * resource.
     * @param authentication authentication containing currently logged user
     * @param targetDomainObject textual representation of the resource
     * @param permission textual representation of the action on the resource
     * @return true if user can perform the action on the given resource
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null ||
                !(authentication.getPrincipal() instanceof UserDetails) ||
                !(targetDomainObject instanceof String) ||
                !(permission instanceof String)){
            return false;
        }

        UserDetails user = (UserDetails) authentication.getPrincipal();
        String targetResource = (String) targetDomainObject;
        String permissionString = (String) permission;

        // check the permissions against all user roles
        for (GrantedAuthority authority : user.getAuthorities()) {
            Role role = permissionsService.getRole(authority.getAuthority());
            if (role == null) {
                // not defined role in permission service, strange, but let us continue...
                continue;
            }

            for (PermissionRule permissionRule : role.getPermissionRules(targetResource)) {
                if (permissionRule.getResource().equals(targetResource) &&
                        permissionRule.getAction().equals(permissionString) &&
                        permissionRule.isAllowed() &&
                        permissionRule.getCondition() == null) {
                    return true;
                }
            }
        }
        return false;
    }


    /**
     * Determine if the given user with defined roles can perform action on the
     * resource with given identification.
     * @param authentication authentication containing currently logged user
     * @param targetId identification of the resource which should be acquired
     * @param targetType textual representation of the resource
     * @param permission textual representation of the action on the resource
     * @return true if user can perform the action on the given resource
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        if (authentication == null ||
                !(authentication.getPrincipal() instanceof UserDetails) ||
                !(permission instanceof String)){
            return false;
        }

        UserDetails user = (UserDetails) authentication.getPrincipal();
        String permissionString = (String) permission;

        // check the permissions against all user roles
        for (GrantedAuthority authority : user.getAuthorities()) {
            Role role = permissionsService.getRole(authority.getAuthority());
            if (role == null) {
                // not defined role in permission service, strange, but let us continue...
                continue;
            }

            for (PermissionRule permissionRule : role.getPermissionRules(targetType)) {
                if (permissionRule.getResource().equals(targetType) &&
                        permissionRule.getAction().equals(permissionString) &&
                        permissionRule.isAllowed()) {

                    // we have to find resource repository, because we were
                    // given resource identification, after that resource is
                    // acquired from the repository and evaluated in specified
                    // condition
                    IResourceRepository repository = permissionsService.getResource(permissionRule.getResource());
                    Optional<Object> resource = repository.findById(targetId);
                    if (!resource.isPresent()) {
                        throw new ResourceNotFoundException("Resource with identification '" + targetId + "' not found");
                    }

                    if (permissionRule.getCondition() != null) {
                        // condition was given, so evaluate it
                        if (permissionRule.getCondition().test(user, resource.get())) {
                            return true;
                        }

                        // if condition was false, we have to continue
                        // evaluating another rules, because some of them might
                        // be truthy and grant access to resource
                    } else {
                        // condition was not given, so the behaviour is the same
                        // as for regular id-less permission check, allow it
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
