package freenet.plugins.belque;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.Test;

/**
 * Unit test for {@link BelqueTest}.
 */
public class BelqueTest {

	private final Belque belque = new Belque();

	@Test
	public void belqueCanRunALoadedPlugin() {
		BelquePlugin simplePlugin = mock(BelquePlugin.class);
		belque.runPlugin(simplePlugin);
		verify(simplePlugin).start();
	}

}
