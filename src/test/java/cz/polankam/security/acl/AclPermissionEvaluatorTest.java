package cz.polankam.security.acl;

import cz.polankam.security.acl.test_utils.DemoPermissionsService;
import cz.polankam.security.acl.test_utils.DemoUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class AclPermissionEvaluatorTest {

    private DemoPermissionsService permissionsService;
    private AclPermissionEvaluator evaluator;
    private Authentication authenticationMock;

    @BeforeEach
    void setUp() {
        permissionsService = new DemoPermissionsService();
        evaluator = new AclPermissionEvaluator(permissionsService);
        authenticationMock = mock(Authentication.class);
    }


    @Test
    void hasPermission_AuthenticationNull() {
        assertFalse(evaluator.hasPermission(null, "user", "view"));
        assertFalse(evaluator.hasPermission(null, 123L, "user", "view"));
    }

    @Test
    void hasPermission_UserMember() {
        when(authenticationMock.getPrincipal()).thenReturn(new DemoUser("user", "USER"));

        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "view"));
        assertFalse(evaluator.hasPermission(authenticationMock, 123L, "group", "edit"));
        assertFalse(evaluator.hasPermission(authenticationMock, 123L, "group", "non-existing"));
        assertFalse(evaluator.hasPermission(authenticationMock, "instance", "view"));
        assertFalse(evaluator.hasPermission(authenticationMock, "instance", "edit"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "join"));
        assertFalse(evaluator.hasPermission(authenticationMock, 123L, "non-existing", "view"));
    }

    @Test
    void hasPermission_UserManager() {
        when(authenticationMock.getPrincipal()).thenReturn(new DemoUser("manager", "USER"));

        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "view"));
        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "edit"));
        assertFalse(evaluator.hasPermission(authenticationMock, 123L, "group", "non-existing"));
        assertFalse(evaluator.hasPermission(authenticationMock, "instance", "view"));
        assertFalse(evaluator.hasPermission(authenticationMock, "instance", "edit"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "join"));
        assertFalse(evaluator.hasPermission(authenticationMock, 123L, "non-existing", "view"));
    }

    @Test
    void hasPermission_AdminManager() {
        when(authenticationMock.getPrincipal()).thenReturn(new DemoUser("manager", "ADMIN"));

        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "view"));
        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "edit"));
        assertFalse(evaluator.hasPermission(authenticationMock, 123L, "group", "non-existing"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "view"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "edit"));
        assertFalse(evaluator.hasPermission(authenticationMock, "instance", "join"));
        assertFalse(evaluator.hasPermission(authenticationMock, 123L, "non-existing", "view"));
    }

    @Test
    void hasPermission_Superadmin() {
        when(authenticationMock.getPrincipal()).thenReturn(new DemoUser("superadmin", "SUPERADMIN"));

        // superadmin can do literally everything
        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "view"));
        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "edit"));
        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "group", "non-existing"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "view"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "edit"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "join"));
        assertTrue(evaluator.hasPermission(authenticationMock, "instance", "non-existing"));
        assertTrue(evaluator.hasPermission(authenticationMock, 123L, "non-existing", "view"));
    }
}