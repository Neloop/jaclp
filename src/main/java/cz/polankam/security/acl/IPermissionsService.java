package cz.polankam.security.acl;

/**
 * Used for management of user roles and privileges, should be the entry point
 * for adding or changing permission related stuff. It is the base for any other
 * authorization services which handles user roles and permissions.
 * Has to be implemented by the one who uses this library.
 *
 * Created by Martin Polanka
 */
public interface IPermissionsService {

    /**
     * Determine if the given role is defined within permission service.
     * @param role textual role representation
     * @return true if role exists, false otherwise
     */
    boolean roleExists(String role);

    /**
     * For the given textual role get its structured representation containing
     * permission rules.
     * @param roleString textual role representation
     * @return structured representation of given textual role or null if not defined
     */
    Role getRole(String roleString);

    /**
     * For the given textual representation of resource return its resource
     * repository.
     * Should throw in case of not defined resource.
     * @param resource textual resource representation
     * @return repository from which resource object can be acquired
     */
    IResourceRepository<?, ?> getResource(String resource);
}
