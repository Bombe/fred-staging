package freenet.node;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import freenet.crypt.DummyRandomSource;
import freenet.crypt.ECDSA;
import freenet.io.comm.PeerParseException;
import freenet.io.comm.ReferenceSignatureVerificationException;
import freenet.support.Base64;
import freenet.support.Logger;
import freenet.support.LoggerHook;
import freenet.support.SimpleFieldSet;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.internal.util.reflection.Whitebox;

import static freenet.node.DarknetPeerNode.FRIEND_TRUST.NORMAL;
import static freenet.support.Logger.LogLevel.MINIMAL;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DarknetPeerNodeTest {

	@Test
	public void readExtraPeerDataDoesNotThrowExceptionIfPeerDataDirectoryDoesNotExist() throws Exception {
		when(node.getExtraPeerDataDir()).thenReturn("/not/existing/directory");
		darknetPeerNode.readExtraPeerData();
	}

	@Test
	public void readExtraPeerDataDoesLogAnErrorIfPeerDataDirectoryIsNotADirectory() throws Exception {
		File extraPeerDataDirectory = temporaryFolder.newFolder();
		new File(extraPeerDataDirectory, darknetPeerNode.getIdentityString()).createNewFile();
		when(node.getExtraPeerDataDir()).thenReturn(extraPeerDataDirectory.getAbsolutePath());

		darknetPeerNode.readExtraPeerData();
		assertThat(loggedMessages, hasItem(startsWith("ERROR: Extra peer data directory for peer not a directory")));
	}

	@Before
	public void addLoggerHook() {
		Logger.globalAddHook(loggerHook);
	}

	@After
	public void removeLoggerHook() {
		Logger.globalRemoveHook(loggerHook);
	}

	private void addSignatureToFieldSet() {
		fieldSet.removeValue("sigP256");
		byte[] signature = key.sign(fieldSet.toOrderedString().getBytes(UTF_8));
		fieldSet.putSingle("sigP256", Base64.encode(signature));
	}

	public DarknetPeerNodeTest() throws PeerTooOldException, FSParseException, ReferenceSignatureVerificationException, PeerParseException {
	}

	private final Node node = mock(Node.class);

	{
		Whitebox.setInternalState(node, "peers", mock(PeerManager.class));
		Whitebox.setInternalState(node, "random", new DummyRandomSource());
	}

	private final NodeCrypto nodeCrypto = mock(NodeCrypto.class);

	{
		nodeCrypto.packetMangler = mock(FNPPacketMangler.class);
		byte[] identityHash = new byte[32];
		new Random().nextBytes(identityHash);
		nodeCrypto.identityHash = identityHash;
		nodeCrypto.identityHashHash = identityHash;
	}

	private final ECDSA key = new ECDSA(ECDSA.Curves.P256);
	private final SimpleFieldSet fieldSet = new SimpleFieldSet(true);

	{
		fieldSet.putSingle("version", "Test,Test,1.0,1234");
		fieldSet.putSingle("auth.negTypes", "1");
		fieldSet.put("ecdsa", key.asFieldSet(false));
		fieldSet.putSingle("identity", "TestIdentity");
		fieldSet.putSingle("myName", "TestNode");
		addSignatureToFieldSet();
	}

	private final DarknetPeerNode darknetPeerNode = new DarknetPeerNode(fieldSet, node, nodeCrypto, false, NORMAL, null);

	private final List<String> loggedMessages = new ArrayList<>();
	private final LoggerHook loggerHook = new LoggerHook(MINIMAL) {
		@Override
		public void log(Object o, Class<?> source, String message, Throwable e, LogLevel priority) {
			loggedMessages.add(priority.name() + ": " + message);
		}
	};

	@Rule
	public final TemporaryFolder temporaryFolder = TemporaryFolder.builder().build();

}
