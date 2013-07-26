/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.clients.http.bookmark;

import java.net.MalformedURLException;

import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.l10n.NodeL10n;
import freenet.node.FSParseException;
import freenet.node.NodeClientCore;
import freenet.node.useralerts.AbstractUserAlert;
import freenet.node.useralerts.UserAlert;
import freenet.node.useralerts.UserAlertManager;
import freenet.support.HTMLNode;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;

public class BookmarkItem extends Bookmark {

	/** Whether we are logging at MINOR. */
	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(BookmarkItem.class);
	}

	private final BookmarkUpdatedUserAlert bookmarkUpdatedUserAlert;

	private final UserAlertManager userAlertManager;

	protected String description;

	protected String shortDescription;

	private FreenetURI key;

	private boolean updated;

	private boolean hasAnActivelink = false;

	public BookmarkItem(FreenetURI key, String name, String description, String shortDescription, boolean hasAnActivelink, UserAlertManager userAlertManager)
			throws MalformedURLException {

		this.key = key;
		setName(name);
		this.description = description;
		this.shortDescription = shortDescription;
		this.hasAnActivelink = hasAnActivelink;
		this.userAlertManager = userAlertManager;
		bookmarkUpdatedUserAlert = new BookmarkUpdatedUserAlert();
		assert (this.key != null);
	}

	public BookmarkItem(SimpleFieldSet simpleFieldSet, UserAlertManager userAlertManager) throws FSParseException, MalformedURLException {
		setName(simpleFieldSet.get("Name"));
		this.description = simpleFieldSet.get("Description");
		if (description == null) {
			description = "";
		}
		this.shortDescription = simpleFieldSet.get("ShortDescription");
		if (shortDescription == null) {
			shortDescription = "";
		}
		this.hasAnActivelink = simpleFieldSet.getBoolean("hasAnActivelink");
		this.key = new FreenetURI(simpleFieldSet.get("URI"));
		this.userAlertManager = userAlertManager;
		this.bookmarkUpdatedUserAlert = new BookmarkUpdatedUserAlert();
	}

	//
	// ACCESSORS
	//

	public String getDescription() {
		if (description == null) {
			return "";
		}
		if (description.toLowerCase().startsWith("l10n:")) {
			return NodeL10n.getBase().getString("Bookmarks.Defaults.Description." + description.substring("l10n:".length()));
		}
		return description;
	}

	public String getShortDescription() {
		if (shortDescription == null) {
			return "";
		}
		if (shortDescription.toLowerCase().startsWith("l10n:")) {
			return NodeL10n.getBase().getString("Bookmarks.Defaults.ShortDescription." + shortDescription.substring("l10n:".length()));
		}
		return shortDescription;
	}

	public synchronized FreenetURI getURI() {
		return key;
	}

	public String getKey() {
		return key.toString();
	}

	public synchronized String getKeyType() {
		return key.getKeyType();
	}

	public USK getUSK() throws MalformedURLException {
		return USK.create(key);
	}

	public boolean hasAnActivelink() {
		return hasAnActivelink;
	}

	//
	// ACTIONS
	//

	public synchronized void update(FreenetURI uri, boolean hasAnActivelink, String description, String shortDescription) {
		this.key = uri;
		this.description = description;
		this.shortDescription = shortDescription;
		this.hasAnActivelink = hasAnActivelink;
		if (!key.isUSK()) {
			disableBookmark();
		}
	}

	/** @return True if we updated the edition */
	public synchronized boolean setEdition(long edition, NodeClientCore nodeClientCore) {
		if (key.getSuggestedEdition() >= edition) {
			if (logMINOR) {
				Logger.minor(this, "Edition " + edition + " is too old, not updating " + key);
			}
			return false;
		}
		key = key.setSuggestedEdition(edition);
		enableBookmark();
		return true;
	}

	//
	// BOOKMARK METHODS
	//

	@Override
	public SimpleFieldSet getSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("Name", getName());
		simpleFieldSet.putSingle("Description", description);
		simpleFieldSet.putSingle("ShortDescription", shortDescription);
		simpleFieldSet.put("hasAnActivelink", hasAnActivelink);
		simpleFieldSet.putSingle("URI", key.toString());
		return simpleFieldSet;
	}

	//
	// OBJECT METHODS
	//

	@Override
	public String toString() {
		return getName() + "###" + (this.description != null ? this.description : "") + "###" + this.hasAnActivelink + "###" + this.key.toString();
	}

	@Override
	public int hashCode() {
		int hash = super.hashCode();
		hash = 31 * hash + this.key.setSuggestedEdition(0).hashCode();
		hash = 31 * hash + (this.hasAnActivelink ? 1 : 0);
		hash = 31 * hash + (this.description != null ? this.description.hashCode() : 0);
		return hash;
	}

	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}
		if (object instanceof BookmarkItem) {
			BookmarkItem bookmarkItem = (BookmarkItem) object;
			if (!super.equals(object)) {
				return false;
			}
			if (!bookmarkItem.key.equals(key)) {
				if ("USK".equals(bookmarkItem.key.getKeyType())) {
					if (!bookmarkItem.key.setSuggestedEdition(key.getSuggestedEdition()).equals(key)) {
						return false;
					}
				} else {
					return false;
				}
			}
			if (bookmarkItem.userAlertManager != userAlertManager) {
				return false;
			} // Belongs to a different node???
			if (bookmarkItem.hasAnActivelink != hasAnActivelink) {
				return false;
			}
			if (bookmarkItem.description.equals(description)) {
				return true;
			}
			if (bookmarkItem.description == null || description == null) {
				return false;
			}
			if (!bookmarkItem.description.equals(description)) {
				return false;
			}
			return true;
		} else {
			return false;
		}
	}

	//
	// PRIVATE METHODS
	//

	private String l10n(String key) {
		return NodeL10n.getBase().getString("BookmarkItem." + key);
	}

	private String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("BookmarkItem." + key, new String[] { pattern }, new String[] { value });
	}

	private String l10n(String key, String[] patterns, String[] values) {
		return NodeL10n.getBase().getString("BookmarkItem." + key, patterns, values);
	}

	//
	// PRIVATE ACTIONS
	//

	private synchronized void enableBookmark() {
		if (updated) {
			return;
		}
		assert (key.isUSK());
		updated = true;
		userAlertManager.register(bookmarkUpdatedUserAlert);
	}

	private synchronized void disableBookmark() {
		updated = false;
		userAlertManager.unregister(bookmarkUpdatedUserAlert);
	}

	private class BookmarkUpdatedUserAlert extends AbstractUserAlert {

		public BookmarkUpdatedUserAlert() {
			super(true, null, null, null, null, UserAlert.MINOR, false, null, true, null);
		}

		//
		// ABSTRACTUSERALERT METHODS
		//

		@Override
		public String getTitle() {
			return l10n("bookmarkUpdatedTitle", "name", getName());
		}

		@Override
		public String getText() {
			return l10n("bookmarkUpdated", new String[] { "name", "edition" },
							   new String[] { getName(), Long.toString(key.getSuggestedEdition()) });
		}

		@Override
		public String getShortText() {
			return l10n("bookmarkUpdatedShort", "name", getName());
		}

		@Override
		public HTMLNode getHTMLText() {
			HTMLNode htmlNode = new HTMLNode("div");
			NodeL10n.getBase().addL10nSubstitution(htmlNode, "BookmarkItem.bookmarkUpdatedWithLink", new String[] { "link", "name", "edition" },
														  new HTMLNode[] { HTMLNode.link("/" + key), HTMLNode.text(getName()), HTMLNode.text(key.getSuggestedEdition()) });
			return htmlNode;
		}

		@Override
		public String dismissButtonText() {
			return l10n("deleteBookmarkUpdateNotification");
		}

		@Override
		public boolean isValid() {
			synchronized (BookmarkItem.this) {
				return updated;
			}
		}

		@Override
		public boolean isEventNotification() {
			return true;
		}

		@Override
		public void isValid(boolean validity) {
			if (validity) {
				return;
			}
			disableBookmark();
		}

		@Override
		public void onDismiss() {
			disableBookmark();
		}

	}

}
