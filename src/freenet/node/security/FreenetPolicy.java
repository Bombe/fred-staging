package freenet.node.security;

import java.security.AllPermission;
import java.security.CodeSource;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;

/**
 * Java Security {@link Policy} implementation that can be the basis for sandboxing plugins.
 * <p>
 * Currently this policy will give out all permissions to anyone asking.
 */
public class FreenetPolicy extends Policy {

	@Override
	public PermissionCollection getPermissions(CodeSource codeSource) {
		Permissions permissions = new Permissions();
		permissions.add(new AllPermission());
		return permissions;
	}

}
