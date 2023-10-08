package freenet.node;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
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
import static freenet.test.SimpleFieldSetMatchers.hasKeyValue;
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
	public void readExtraPeerDataDoesNotThrowExceptionIfPeerDataDirectoryDoesNotExist() {
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
		writePeerNote("extraPeerDataType", "1");

		List<SimpleFieldSet> capturedFieldSets = new ArrayList<>();
		List<Integer> capturedFileNumbers = new ArrayList<>();
		doAnswer(invocation -> {
			capturedFieldSets.add(((SimpleFieldSet) invocation.getArguments()[0]));
			capturedFileNumbers.add((int) invocation.getArguments()[2]);
			return null;
		}).when(node).handleNodeToNodeTextMessageSimpleFieldSet(anyObject(), anyObject(), anyInt());

		darknetPeerNode.readExtraPeerData();
		assertThat(capturedFieldSets, containsInAnyOrder(hasKeyValue("extraPeerDataType", "1")));
		assertThat(capturedFileNumbers, contains(equalTo(0)));
	}

	@Test
	public void readExtraPeerDataHandlesBookmarkMessage() throws Exception {
		writePeerNote("extraPeerDataType", "4");

		List<SimpleFieldSet> capturedFieldSets = new ArrayList<>();
		List<Integer> capturedFileNumbers = new ArrayList<>();
		DarknetPeerNode darknetPeerNode = new DarknetPeerNode(fieldSet, node, nodeCrypto, false, NORMAL, null) {
			@Override
			public void handleFproxyBookmarkFeed(SimpleFieldSet fieldSet, int fileNumber) {
				capturedFieldSets.add(fieldSet);
				capturedFileNumbers.add(fileNumber);
			}
		};
		darknetPeerNode.readExtraPeerData();
		assertThat(capturedFieldSets, containsInAnyOrder(hasKeyValue("extraPeerDataType", "4")));
		assertThat(capturedFileNumbers, contains(equalTo(0)));
	}

	@Test
	public void readExtraPeerDataHandlesDownloadMessage() throws Exception {
		writePeerNote("extraPeerDataType", "5");

		List<SimpleFieldSet> capturedFieldSets = new ArrayList<>();
		List<Integer> capturedFileNumbers = new ArrayList<>();
		DarknetPeerNode darknetPeerNode = new DarknetPeerNode(fieldSet, node, nodeCrypto, false, NORMAL, null) {
			@Override
			public void handleFproxyDownloadFeed(SimpleFieldSet fieldSet, int fileNumber) {
				capturedFieldSets.add(fieldSet);
				capturedFileNumbers.add(fileNumber);
			}
		};
		darknetPeerNode.readExtraPeerData();
		assertThat(capturedFieldSets, containsInAnyOrder(hasKeyValue("extraPeerDataType", "5")));
		assertThat(capturedFileNumbers, contains(equalTo(0)));
	}

	private void writePeerNote(String... keysAndValues) throws IOException {
		setUpPeerNoteDirectory();
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		for (int keyValueIndex = 0; keyValueIndex < keysAndValues.length; keyValueIndex += 2) {
			simpleFieldSet.putSingle(keysAndValues[keyValueIndex], keysAndValues[keyValueIndex + 1]);
		}
		try (OutputStream noteOutputStream = newOutputStream(peerNoteDirectory.toPath().resolve(String.valueOf(nextPeerNoteFileNumber)))) {
			simpleFieldSet.writeTo(noteOutputStream);
		}
		nextPeerNoteFileNumber++;
	}

	private void setUpPeerNoteDirectory() throws IOException {
		setUpNodeExtraPeerDataDirectory();
		if (peerNoteDirectory == null) {
			peerNoteDirectory = new File(nodeExtraPeerDataDirectory, darknetPeerNode.getIdentityString());
			peerNoteDirectory.mkdir();
		}
	}

	private void setUpNodeExtraPeerDataDirectory() throws IOException {
		if (nodeExtraPeerDataDirectory == null) {
			nodeExtraPeerDataDirectory = temporaryFolder.newFolder();
			when(node.getExtraPeerDataDir()).thenReturn(nodeExtraPeerDataDirectory.getPath());
		}
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

	private File nodeExtraPeerDataDirectory;
	private File peerNoteDirectory;
	private int nextPeerNoteFileNumber = 0;

	private final DarknetPeerNode darknetPeerNode = new DarknetPeerNode(fieldSet, node, nodeCrypto, false, NORMAL, null);

	@Rule
	public final CaptureLogger captureLogger = new CaptureLogger();

	@Rule
	public final TemporaryFolder temporaryFolder = TemporaryFolder.builder().build();

}
