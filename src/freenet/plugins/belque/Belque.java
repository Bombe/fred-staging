package freenet.plugins.belque;

/**
 * The main component of Belque, Fred’s plugin API 2.0.
 */
public class Belque {

	public void runPlugin(final BelquePlugin belquePlugin) {
		belquePlugin.start();
	}

}
