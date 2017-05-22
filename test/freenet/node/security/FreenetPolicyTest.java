package freenet.node.security;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.security.AllPermission;
import java.security.CodeSource;
import java.security.PermissionCollection;
import java.security.Policy;

import org.junit.Test;

/**
 * Unit test for {@link FreenetPolicyTest}.
 */
public class FreenetPolicyTest {

	private final Policy freenetPolicy = new FreenetPolicy();

	@Test
	public void policyReturnsAllPermissionsForNullCodeSource() {
		PermissionCollection permissionCollection = freenetPolicy.getPermissions((CodeSource) null);
		assertThat(permissionCollection.implies(new AllPermission()), equalTo(true));
	}

	@Test
	public void policyReturnsAllPermissionsForTestClassLoader() {
		PermissionCollection permissionCollection = freenetPolicy.getPermissions(getClass().getProtectionDomain().getCodeSource());
		assertThat(permissionCollection.implies(new AllPermission()), equalTo(true));
	}

}
