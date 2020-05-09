package cz.polankam.security.acl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.transaction.PlatformTransactionManager;

/**
 * Spring configuration support for JACLP library, which initializes all needed
 * beans.
 */
@Configuration
public class JaclpSpringConfiguration {

    @Lazy
    @Autowired
    private AclPermissionEvaluator permissionEvaluator;

    @Bean
    @Autowired
    public AclPermissionEvaluator aclPermissionEvaluator(IPermissionsService permissionsService, PlatformTransactionManager transactionManager) {
        return new AclPermissionEvaluator(permissionsService, transactionManager);
    }

    @Bean
    public AuthorizatorService authorizatorService() {
        return new AuthorizatorService(permissionEvaluator);
    }
}
