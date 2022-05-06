package freenet.node;

public class DarknetPeerNodeStatus extends PeerNodeStatus {

	private final String name;

	private final boolean burstOnly;

	private final boolean listening;

	private final boolean disabled;

	private final String privateDarknetCommentNote;
	
	private DarknetPeerNode.FRIEND_TRUST trustLevel;

	private DarknetPeerNode.FRIEND_VISIBILITY ourVisibility;
	private DarknetPeerNode.FRIEND_VISIBILITY theirVisibility;
	private DarknetPeerNode.FRIEND_VISIBILITY overallVisibility;
	
	public DarknetPeerNodeStatus(DarknetPeerNode peerNode, boolean noHeavy) {
		super(peerNode, noHeavy);
		this.name = peerNode.getName();
		this.burstOnly = peerNode.isBurstOnly();
		this.listening = peerNode.isListenOnly();
		this.disabled = peerNode.isDisabled();
		this.privateDarknetCommentNote = peerNode.getPrivateDarknetCommentNote();
		this.trustLevel = peerNode.getTrustLevel();
		this.ourVisibility = peerNode.getOurVisibility();
		this.theirVisibility = peerNode.getTheirVisibility();
		if(ourVisibility.isStricterThan(theirVisibility))
			this.overallVisibility = ourVisibility;
		else
			this.overallVisibility = theirVisibility;
	}
	
	/**
	 * @return The peer's trust level.
	 */
	public DarknetPeerNode.FRIEND_TRUST getTrustLevel() {
		return trustLevel;
	}
	
	/**
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return the burstOnly
	 */
	public boolean isBurstOnly() {
		return burstOnly;
	}

	/**
	 * @return the disabled
	 */
	public boolean isDisabled() {
		return disabled;
	}

	/**
	 * @return the listening
	 */
	public boolean isListening() {
		return listening;
	}

	/**
	 * @return the privateDarknetCommentNote
	 */
	public String getPrivateDarknetCommentNote() {
		return privateDarknetCommentNote;
	}

	@Override
	public String toString() {
		return name + ' ' + super.toString();
	}

	public DarknetPeerNode.FRIEND_VISIBILITY getOurVisibility() {
		return ourVisibility;
	}
	
	public DarknetPeerNode.FRIEND_VISIBILITY getTheirVisibility() {
		if(theirVisibility == null)
			return DarknetPeerNode.FRIEND_VISIBILITY.NO;
		return theirVisibility;
	}
	
	public DarknetPeerNode.FRIEND_VISIBILITY getOverallVisibility() {
		return overallVisibility;
	}
}
