package freenet.clients.http.bookmark;

import freenet.l10n.NodeL10n;
import freenet.support.SimpleFieldSet;

/**
 * Base class for all bookmark-related items. Both categories and bookmark items
 * derive from this class.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 *         (after refactoring)
 */
public abstract class Bookmark {

	/** The name of the bookmark. */
	private String name;

	//
	// ACCESSORS
	//

	/**
	 * Returns the name of this bookmark.
	 *
	 * @return The name of this bookmark
	 */
	public final String getName() {
		return name;
	}

	/**
	 * Returns the visible name of this bookmark. If the name of this bookmark
	 * starts with “l10n:” its visible name is taken from the translation;
	 * otherwise, the name of this bookmark is returned.
	 *
	 * @return The visible name of this bookmark
	 */
	public String getVisibleName() {
		if (name.toLowerCase().startsWith("l10n:")) {
			return NodeL10n.getBase().getString("Bookmarks.Defaults.Name." + name.substring("l10n:".length()));
		}
		return name;
	}

	/**
	 * Sets the name of this bookmark. If the given name is {@code null} or empty,
	 * a default bookmark name is used.
	 *
	 * @param name
	 * 		The new name of this bookmark
	 */
	protected void setName(String name) {
		this.name = ((name == null) || (name.length() > 0)) ? name : NodeL10n.getBase().getString("Bookmark.noName");
	}

	//
	// SUBLCASS METHODS
	//

	/**
	 * Returns a simple field set describing this bookmark.
	 *
	 * @return A simple field set describing this bookmark
	 */
	public abstract SimpleFieldSet getSimpleFieldSet();

	//
	// OBJECT METHODS
	//

	@Override
	public boolean equals(Object object) {
		if (object == this) {
			return true;
		}
		if (object instanceof Bookmark) {
			Bookmark bookmark = (Bookmark) object;
			if (!bookmark.name.equals(name)) {
				return false;
			}
			return true;
		} else {
			return false;
		}
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

}
