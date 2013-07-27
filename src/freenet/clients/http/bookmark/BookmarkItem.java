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

	/** The user alert for an userAlertShowing bookmark. */
	private final BookmarkUpdatedUserAlert bookmarkUpdatedUserAlert = new BookmarkUpdatedUserAlert();

	/** The user alert manager. */
	private final UserAlertManager userAlertManager;

	/** The description of the bookmark. */
	protected String description;

	/** The short description of the bookmark. */
	protected String shortDescription;

	/** The key of the bookmark. */
	private FreenetURI key;

	/** Whether the bookmark has been updated and the alert is showing. */
	private boolean userAlertShowing;

	/** Whether the bookmark has an activelink image. */
	private boolean hasAnActivelink = false;

	/**
	 * Creates a new bookmark item.
	 *
	 * @param key
	 * 		The key of the bookmark
	 * @param name
	 * 		The name of the bookmark
	 * @param description
	 * 		The description of the bookmark
	 * @param shortDescription
	 * 		The short description of the bookmark
	 * @param hasAnActivelink
	 * 		{@code true} if the bookmark has an activelink image, {@code false}
	 * 		otherwise
	 * @param userAlertManager
	 * 		The user alert manager
	 */
	public BookmarkItem(FreenetURI key, String name, String description, String shortDescription, boolean hasAnActivelink, UserAlertManager userAlertManager) {
		this.key = key;
		setName(name);
		this.description = description;
		this.shortDescription = shortDescription;
		this.hasAnActivelink = hasAnActivelink;
		this.userAlertManager = userAlertManager;
		assert (this.key != null);
	}

	/**
	 * Creates a new bookmark item from the given simple field set.
	 *
	 * @param simpleFieldSet
	 * 		The simple field set to parse the bookmark item from
	 * @param userAlertManager
	 * 		The user alert manager
	 * @throws FSParseException
	 * 		if the field set can not be parsed
	 * @throws MalformedURLException
	 * 		if the bookmark key is malformed
	 */
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
	}

	//
	// ACCESSORS
	//

	/**
	 * Returns the description of this bookmark item. If the description starts
	 * with “l10n:” it is taken from the translation.
	 *
	 * @return The description of this bookmark item
	 */
	public String getDescription() {
		if (description == null) {
			return "";
		}
		if (description.toLowerCase().startsWith("l10n:")) {
			return NodeL10n.getBase().getString("Bookmarks.Defaults.Description." + description.substring("l10n:".length()));
		}
		return description;
	}

	/**
	 * Returns the short description of this bookmark item. If the short
	 * description starts with “l10n:” it is taken from the translation.
	 *
	 * @return The short description of this bookmark item
	 */
	public String getShortDescription() {
		if (shortDescription == null) {
			return "";
		}
		if (shortDescription.toLowerCase().startsWith("l10n:")) {
			return NodeL10n.getBase().getString("Bookmarks.Defaults.ShortDescription." + shortDescription.substring("l10n:".length()));
		}
		return shortDescription;
	}

	/**
	 * Returns the key of this bookmark item.
	 *
	 * @return The key of this bookmark item
	 */
	public synchronized FreenetURI getURI() {
		return key;
	}

	/**
	 * Returns the key of this bookmark item.
	 *
	 * @return The key of this bookmark item
	 */
	public String getKey() {
		return key.toString();
	}

	/**
	 * Returns the key type of this bookmark item’s key.
	 *
	 * @return The key type of this bookmark item’s key
	 */
	public synchronized String getKeyType() {
		return key.getKeyType();
	}

	/**
	 * Returns the key of this bookmark item as a USK.
	 *
	 * @return The key of this bookmark item as a USK
	 * @throws MalformedURLException
	 * 		if the key can not be converted to a USK
	 */
	public USK getUSK() throws MalformedURLException {
		return USK.create(key);
	}

	/**
	 * Returns whether this bookmark item has an activelink image.
	 *
	 * @return {@code true} if this bookmark item has an activelink image, {@code
	 *         false} otherwise
	 */
	public boolean hasAnActivelink() {
		return hasAnActivelink;
	}

	//
	// ACTIONS
	//

	/**
	 * Updates this bookmark item.
	 *
	 * @param uri
	 * 		The new URI of this bookmark item
	 * @param hasAnActivelink
	 * 		{@code true} if this bookmark item has an activelink image, {@code false}
	 * 		otherwise
	 * @param description
	 * 		The new description of this bookmark item
	 * @param shortDescription
	 * 		The new short description of this bookmark item
	 */
	public synchronized void update(FreenetURI uri, boolean hasAnActivelink, String description, String shortDescription) {
		this.key = uri;
		this.description = description;
		this.shortDescription = shortDescription;
		this.hasAnActivelink = hasAnActivelink;
		if (!key.isUSK()) {
			hideUserAlert();
		}
	}

	/**
	 * Notifies this bookmark item that an edition was found. If the found edition
	 * is newer than the current known edition of this bookmark item, the user
	 * alert is shown.
	 *
	 * @param edition
	 * 		The edition that was found
	 * @param nodeClientCore
	 * 		The node client core
	 * @return {@code true} if we updated the edition, {@code false} if the given
	 *         edition was not newer than the current edition
	 */
	public synchronized boolean setEdition(long edition, NodeClientCore nodeClientCore) {
		if (key.getSuggestedEdition() >= edition) {
			if (logMINOR) {
				Logger.minor(this, "Edition " + edition + " is too old, not updating " + key);
			}
			return false;
		}
		key = key.setSuggestedEdition(edition);
		showUserAlert();
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
		if (!(object instanceof BookmarkItem)) {
			return false;
		}
		BookmarkItem bookmarkItem = (BookmarkItem) object;
		if (!super.equals(object)) {
			return false;
		}
		if (!bookmarkItem.key.setSuggestedEdition(0).equals(key.setSuggestedEdition(0))) {
			return false;
		}
		if (bookmarkItem.hasAnActivelink != hasAnActivelink) {
			return false;
		}
		if (((description == null) && (bookmarkItem.description != null)) || ((description != null) && !description.equals(bookmarkItem.description))) {
			return false;
		}
		return true;
	}

	//
	// PRIVATE METHODS
	//

	/**
	 * Returns the translation for the given key, prepended by “BookmarkItem.”
	 *
	 * @param key
	 * 		The key to retrieve the translation for
	 * @return The translation
	 */
	private static String l10n(String key) {
		return NodeL10n.getBase().getString("BookmarkItem." + key);
	}

	/**
	 * Returns the translation for the given key, prepended by “BookmarkItem.” with
	 * the given pattern replaced by the given value.
	 *
	 * @param key
	 * 		The key to retrieve the translation for
	 * @param pattern
	 * 		The pattern to replace
	 * @param value
	 * 		The value to replace the pattern with
	 * @return The translation
	 */
	private static String l10n(String key, String pattern, String value) {
		return NodeL10n.getBase().getString("BookmarkItem." + key, new String[] { pattern }, new String[] { value });
	}

	/**
	 * Returns the translation for the given key, prepended by “BookmarkItem.” with
	 * the given patterns replaced by the given values.
	 *
	 * @param key
	 * 		The key to retrieve the translation for
	 * @param patterns
	 * 		The patterns to replace
	 * @param values
	 * 		The values to replace the patterns with
	 * @return The translation
	 */
	private static String l10n(String key, String[] patterns, String[] values) {
		return NodeL10n.getBase().getString("BookmarkItem." + key, patterns, values);
	}

	//
	// PRIVATE ACTIONS
	//

	/** Shows the user alert if it isn’t already showing. */
	private synchronized void showUserAlert() {
		if (userAlertShowing) {
			return;
		}
		assert (key.isUSK());
		userAlertShowing = true;
		userAlertManager.register(bookmarkUpdatedUserAlert);
	}

	/** Hides the user alert. */
	private synchronized void hideUserAlert() {
		userAlertShowing = false;
		userAlertManager.unregister(bookmarkUpdatedUserAlert);
	}

	/**
	 * The user alert for an updated bookmark.
	 *
	 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
	 *         (after refactoring)
	 */
	private class BookmarkUpdatedUserAlert extends AbstractUserAlert {

		/** Creates a new bookmark updated user alert. */
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
				return userAlertShowing;
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
			hideUserAlert();
		}

		@Override
		public void onDismiss() {
			hideUserAlert();
		}

	}

}
