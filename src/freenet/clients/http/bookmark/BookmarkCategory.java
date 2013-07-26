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
	 * @param simpleFieldSet
	 * 		The simple field set to create a bookmark category from
	 * @throws FSParseException
	 * 		if the simple field set can not be parsed
	 */
	public BookmarkCategory(SimpleFieldSet simpleFieldSet) throws FSParseException {
		String name = simpleFieldSet.get("Name");
		if (name == null) {
			throw new FSParseException("No Name!");
		}
		setName(name);
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
	 * Returns the <i>index</i>th bookmark in this category.
	 *
	 * @param index
	 * 		The index of the bookmark
	 * @return The bookmark at the given index
	 */
	public synchronized Bookmark get(int index) {
		return bookmarks.get(index);
	}

	/**
	 * Returns all bookmark items in this category.
	 *
	 * @return All bookmark items in this category
	 */
	public synchronized List<BookmarkItem> getItems() {
		List<BookmarkItem> items = new ArrayList<BookmarkItem>();
		for (Bookmark bookmark : bookmarks) {
			if (bookmark instanceof BookmarkItem) {
				items.add((BookmarkItem) bookmark);
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
		for (BookmarkCategory category : getSubCategories()) {
			items.addAll(category.getAllItems());
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
		for (Bookmark bookmark : bookmarks) {
			if (bookmark instanceof BookmarkCategory) {
				categories.add((BookmarkCategory) bookmark);
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
	 * @param bookmark
	 * 		The bookmark to add
	 * @return The existing bookmark if it already existed, or the added bookmark
	 *         if it was added
	 */
	protected synchronized Bookmark addBookmark(Bookmark bookmark) {
		if (bookmark == null) {
			return null;
		}
		// Overwrite any existing bookmark
		int x = bookmarks.indexOf(bookmark);
		if (x >= 0) {
			return bookmarks.get(x);
		}
		bookmarks.add(bookmark);
		return bookmark;
	}

	/**
	 * Removes the given bookmark from this category.
	 *
	 * @param bookmark
	 */
	protected synchronized void removeBookmark(Bookmark bookmark) {
		bookmarks.remove(bookmark);
	}

	/**
	 * Moves the given bookmark up in this category.
	 *
	 * @param bookmark
	 * 		The bookmark to move up
	 */
	protected synchronized void moveBookmarkUp(Bookmark bookmark) {
		int index = bookmarks.indexOf(bookmark);
		if (index == -1) {
			return;
		}

		Bookmark removedBookmark = bookmarks.remove(index);
		bookmarks.add((--index < 0) ? 0 : index, removedBookmark);
	}

	/**
	 * Moves the given bookmark down in this category
	 *
	 * @param bookmark
	 * 		The bookmark to move down
	 */
	protected synchronized void moveBookmarkDown(Bookmark bookmark) {
		int index = bookmarks.indexOf(bookmark);
		if (index == -1) {
			return;
		}

		Bookmark removedBookmark = bookmarks.remove(index);
		bookmarks.add((++index > size()) ? size() : index, removedBookmark);
	}

	//
	// BOOKMARK METHODS
	//

	@Override
	public synchronized SimpleFieldSet getSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("Name", getName());
		simpleFieldSet.put("Content", BookmarkManager.toSimpleFieldSet(this));
		return simpleFieldSet;
	}

}
