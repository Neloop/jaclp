package cz.polankam.security.acl;

import java.util.Optional;

/**
 * Interface for resource repository which can be used to acquire resources in
 * permission evaluator.
 * @param <EntityType> type of the entity
 * @param <KeyType> type of the entity identification
 *
 * Created by Martin Polanka
 */
public interface IResourceRepository<EntityType, KeyType> {

    /**
     * Find resource entity based on given identification.
     * @param id identification of resource
     * @return entity resource
     */
    Optional<EntityType> findById(KeyType id);
}
