package freenet.client.async;

import freenet.support.node.UserAlert;

// TODO: Modularity: Make UserAlertManager implement this
public interface UserAlertRegister {

	void register(UserAlert alert);

}
