package cz.polankam.security.acl;

import java.util.Optional;

/**
 * Interface for resource repository which can be used to acquire resources in
 * permission evaluator.
 * <p>
 * Created by Martin Polanka
 */
public interface IResourceRepository {

    /**
     * Find resource entity based on given identification.
     *
     * @param id identification of resource
     * @return entity resource
     */
    Optional<Object> findById(Object id);
}
