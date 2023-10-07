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
import freenet.support.SimpleFieldSet;
import freenet.test.CaptureLogger;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.internal.util.reflection.Whitebox;

import static freenet.node.DarknetPeerNode.FRIEND_TRUST.NORMAL;
import static freenet.test.SimpleFieldSetMatcher.matches;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.newOutputStream;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Mockito.doAnswer;
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
		assertThat(captureLogger.getLoggedMessages(), hasItem(startsWith("ERROR: Extra peer data directory for peer not a directory")));
	}

	@Test
	public void readExtraPeerDataHandsMessageToNode() throws Exception {
		File extraPeerDataDirectory = temporaryFolder.newFolder(darknetPeerNode.getIdentityString());
		when(node.getExtraPeerDataDir()).thenReturn(extraPeerDataDirectory.getParent());
		SimpleFieldSet node2NodeTextMessage = new SimpleFieldSet(true);
		node2NodeTextMessage.putSingle("extraPeerDataType", "1");
		node2NodeTextMessage.writeTo(newOutputStream(extraPeerDataDirectory.toPath().resolve("0")));

		List<SimpleFieldSet> capturedFieldSets = new ArrayList<>();
		List<Integer> capturedFileNumbers = new ArrayList<>();
		doAnswer(invocation -> {
			capturedFieldSets.add(((SimpleFieldSet) invocation.getArguments()[0]));
			capturedFileNumbers.add((int) invocation.getArguments()[2]);
			return null;
		}).when(node).handleNodeToNodeTextMessageSimpleFieldSet(anyObject(), anyObject(), anyInt());

		darknetPeerNode.readExtraPeerData();
		assertThat(capturedFieldSets, containsInAnyOrder(matches(node2NodeTextMessage)));
		assertThat(capturedFileNumbers, contains(equalTo(0)));
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

	@Rule
	public final CaptureLogger captureLogger = new CaptureLogger();

	@Rule
	public final TemporaryFolder temporaryFolder = TemporaryFolder.builder().build();

}
