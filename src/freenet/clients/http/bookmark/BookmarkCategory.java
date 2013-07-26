package freenet.clients.http.bookmark;

import java.util.ArrayList;
import java.util.List;

import freenet.node.FSParseException;
import freenet.support.SimpleFieldSet;

/**
 * Bookmark category that can contain arbitrary other {@link Bookmark}
 * categories and items.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 *         (after refactoring)
 */
public class BookmarkCategory extends Bookmark {

	/** The bookmarks contained in this category. */
	private final List<Bookmark> bookmarks = new ArrayList<Bookmark>();

	/**
	 * Creates a new bookmark category.
	 *
	 * @param name
	 * 		The name of this category
	 */
	public BookmarkCategory(String name) {
		setName(name);
	}

	/**
	 * Creates a new bookmark category.
	 *
	 * @param sfs
	 * 		The simple field set to create a bookmark category from
	 * @throws FSParseException
	 * 		if the simple field set can not be parsed
	 */
	public BookmarkCategory(SimpleFieldSet sfs) throws FSParseException {
		String aName = sfs.get("Name");
		if (aName == null) {
			throw new FSParseException("No Name!");
		}
		setName(aName);
	}

	//
	// ACCESSORS
	//

	/**
	 * Returns the number of bookmarks contained in this category.
	 *
	 * @return The number of bookmarks contained in this category
	 */
	public synchronized int size() {
		return bookmarks.size();
	}

	/**
	 * Returns the <i>i</i>th bookmark in this category.
	 *
	 * @param i
	 * 		The index of the bookmark
	 * @return The bookmark at the given index
	 */
	public synchronized Bookmark get(int i) {
		return bookmarks.get(i);
	}

	/**
	 * Returns all bookmark items in this category.
	 *
	 * @return All bookmark items in this category
	 */
	public synchronized List<BookmarkItem> getItems() {
		List<BookmarkItem> items = new ArrayList<BookmarkItem>();
		for (Bookmark b : bookmarks) {
			if (b instanceof BookmarkItem) {
				items.add((BookmarkItem) b);
			}
		}
		return items;
	}

	/**
	 * Returns all bookmark items in this category and all sub categories.
	 *
	 * @return All bookmark items in this category and all sub categories
	 */
	public synchronized List<BookmarkItem> getAllItems() {
		List<BookmarkItem> items = getItems();
		for (BookmarkCategory cat : getSubCategories()) {
			items.addAll(cat.getAllItems());
		}
		return items;
	}

	/**
	 * Returns all categories contained in this category.
	 *
	 * @return All categories contained in this category
	 */
	public synchronized List<BookmarkCategory> getSubCategories() {
		List<BookmarkCategory> categories = new ArrayList<BookmarkCategory>();
		for (Bookmark b : bookmarks) {
			if (b instanceof BookmarkCategory) {
				categories.add((BookmarkCategory) b);
			}
		}
		return categories;
	}

	//
	// ACTIONS
	//

	/**
	 * Adds the given bookmark to this category.
	 *
	 * @param b
	 * 		The bookmark to add
	 * @return The existing bookmark if it already existed, or the added bookmark
	 *         if it was added
	 */
	protected synchronized Bookmark addBookmark(Bookmark b) {
		if (b == null) {
			return null;
		}
		// Overwrite any existing bookmark
		int x = bookmarks.indexOf(b);
		if (x >= 0) {
			return bookmarks.get(x);
		}
		bookmarks.add(b);
		return b;
	}

	/**
	 * Removes the given bookmark from this category.
	 *
	 * @param b
	 */
	protected synchronized void removeBookmark(Bookmark b) {
		bookmarks.remove(b);
	}

	/**
	 * Moves the given bookmark up in this category.
	 *
	 * @param b
	 * 		The bookmark to move up
	 */
	protected synchronized void moveBookmarkUp(Bookmark b) {
		int index = bookmarks.indexOf(b);
		if (index == -1) {
			return;
		}

		Bookmark bk = bookmarks.remove(index);
		bookmarks.add((--index < 0) ? 0 : index, bk);
	}

	/**
	 * Moves the given bookmark down in this category
	 *
	 * @param b
	 * 		The bookmark to move down
	 */
	protected synchronized void moveBookmarkDown(Bookmark b) {
		int index = bookmarks.indexOf(b);
		if (index == -1) {
			return;
		}

		Bookmark bk = bookmarks.remove(index);
		bookmarks.add((++index > size()) ? size() : index, bk);
	}

	//
	// BOOKMARK METHODS
	//

	@Override
	public synchronized SimpleFieldSet getSimpleFieldSet() {
		SimpleFieldSet sfs = new SimpleFieldSet(true);
		sfs.putSingle("Name", getName());
		sfs.put("Content", BookmarkManager.toSimpleFieldSet(this));
		return sfs;
	}

}
