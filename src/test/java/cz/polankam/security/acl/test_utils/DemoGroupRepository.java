package cz.polankam.security.acl.test_utils;

import cz.polankam.security.acl.IResourceRepository;

import java.util.Optional;

/**
 * Demo group service for getting DemoGroup.
 */
public class DemoGroupRepository implements IResourceRepository<DemoGroup, Long> {

    @Override
    public Optional<DemoGroup> findById(Long id) {
        return Optional.of(new DemoGroup());
    }
}
