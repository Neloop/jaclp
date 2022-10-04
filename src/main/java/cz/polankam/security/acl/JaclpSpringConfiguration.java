package cz.polankam.security.acl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.Optional;

/**
 * Spring configuration support for JACLP library, which initializes all needed
 * beans.
 */
@Configuration
public class JaclpSpringConfiguration {

    @Bean
    @Autowired
    public AclPermissionEvaluator aclPermissionEvaluator(IPermissionsService permissionsService, Optional<PlatformTransactionManager> transactionManager) {
        return new AclPermissionEvaluator(permissionsService, transactionManager.orElse(null));
    }

    @Bean
    public AuthorizatorService authorizatorService(AclPermissionEvaluator permissionEvaluator) {
        return new AuthorizatorService(permissionEvaluator);
    }
}
