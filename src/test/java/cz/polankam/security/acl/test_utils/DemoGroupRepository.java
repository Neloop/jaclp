package cz.polankam.security.acl.test_utils;

import cz.polankam.security.acl.IResourceRepository;

import java.util.Optional;

/**
 * Demo group service for getting DemoGroup.
 */
public class DemoGroupRepository implements IResourceRepository {

    @Override
    public Optional<Object> findById(Object id) {
        return Optional.of(new DemoGroup());
    }
}
