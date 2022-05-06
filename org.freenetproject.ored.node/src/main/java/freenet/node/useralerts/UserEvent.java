package freenet.node.useralerts;

import freenet.clients.fcp.FCPUserAlert;

public interface UserEvent extends FCPUserAlert {
	public enum Type {
		Announcer(true), GetCompleted, PutCompleted, PutDirCompleted;

		private boolean unregisterIndefinitely;

		private Type(boolean unregisterIndefinetely) {
			this.unregisterIndefinitely = unregisterIndefinetely;
		}

		private Type() {
			unregisterIndefinitely = false;
		}

		/**
		 *
		 * @return true if the unregistration of one event of this type
		 *         should prevent future events of the same type from being displayed
		 */
		public boolean unregisterIndefinitely() {
			return unregisterIndefinitely;
		}
	};

	/**
	 *
	 * @return The type of the event
	 */
	public Type getEventType();
}
