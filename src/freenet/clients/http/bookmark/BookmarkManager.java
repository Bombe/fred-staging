/* This code is part of Freenet. It is distributed under the GNU General
 * Public License, version 2 (or at your option any later version). See
 * http://www.gnu.org/ for further details of the GPL. */

package freenet.clients.http.bookmark;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import freenet.client.async.ClientContext;
import freenet.client.async.USKCallback;
import freenet.clients.http.FProxyToadlet;
import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.l10n.NodeL10n;
import freenet.node.FSParseException;
import freenet.node.NodeClientCore;
import freenet.node.RequestClient;
import freenet.node.RequestStarter;
import freenet.support.Logger;
import freenet.support.SimpleFieldSet;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import com.db4o.ObjectContainer;

/**
 * Manages bookmarks.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 *         (after refactoring)
 */
public class BookmarkManager implements RequestClient {

	/** Whether we should log at MINOR. */
	private static volatile boolean logMINOR;

	static {
		Logger.registerClass(BookmarkManager.class);
	}

	/** The default bookmarks, read from the classpath. */
	public static final SimpleFieldSet DEFAULT_BOOKMARKS;

	static {
		String name = "freenet/clients/http/staticfiles/defaultbookmarks.dat";
		SimpleFieldSet defaultBookmarks = null;
		InputStream in = null;
		try {
			ClassLoader loader = BookmarkManager.class.getClassLoader();

			// Returns null on lookup failures:
			in = loader.getResourceAsStream(name);
			if (in != null) {
				defaultBookmarks = SimpleFieldSet.readFrom(in, false, false);
			}
		} catch (Exception e) {
			Logger.error(BookmarkManager.class, "Error while loading the default bookmark file from " + name + " :" + e.getMessage(), e);
		} finally {
			Closer.close(in);
			DEFAULT_BOOKMARKS = defaultBookmarks;
		}
	}

	/** The main category. */
	public static final BookmarkCategory MAIN_CATEGORY = new BookmarkCategory("/");

	/** The category for public gateway vistors without full access. */
	public static final BookmarkCategory DEFAULT_CATEGORY = new BookmarkCategory("\\");

	/** The priority to start bookmark update requests at. */
	private static final short PRIORITY = RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS;

	/** The priority to for requests after progress has been made. */
	private static final short PRIORITY_PROGRESS = RequestStarter.UPDATE_PRIORITY_CLASS;

	/** Name for bookmarks in simple field set serialization. */
	private static final String BOOKMARK_NAME = "Bookmark";

	/** Name for bookmark categories in simple field set serialization. */
	private static final String BOOKMARK_CATEGORY_NAME = "BookmarkCategory";

	/** The node client core. */
	private final NodeClientCore nodeClientCore;

	/** The callbacks for updated USKs. */
	private final USKUpdatedCallback uskUpdatedCallback = new USKUpdatedCallback();

	/** The bookmarks. */
	private final Map<String, Bookmark> bookmarks = new HashMap<String, Bookmark>();

	/** The file from which the bookmarks are read. */
	private final File bookmarksFile;

	/** The backup file for the bookmarks. */
	private final File backupBookmarksFile;

	/** Whether we are currently saving the bookmarks. */
	private boolean savingBookmarks = false;

	/** Whether we are currently waiting to save to save the bookmarks. */
	private boolean savingBookmarksLazy = false;

	/**
	 * Creates a new bookmark manager.
	 *
	 * @param nodeClientCore
	 * 		The node client core
	 * @param publicGateway
	 * 		{@code true} if the node is running as a public gateway, {@code false}
	 * 		otherwise
	 */
	public BookmarkManager(NodeClientCore nodeClientCore, File bookmarksFile, File backupBookmarksFile, boolean publicGateway) {
		putPaths("/", MAIN_CATEGORY);
		this.nodeClientCore = nodeClientCore;
		this.bookmarksFile = bookmarksFile;
		this.backupBookmarksFile = backupBookmarksFile;

		try {
			// Read the backup file if necessary
			if (!bookmarksFile.exists() || bookmarksFile.length() == 0) {
				throw new IOException();
			}
			Logger.normal(this, "Attempting to read the bookmark file from " + bookmarksFile.toString());
			SimpleFieldSet simpleFieldSet = SimpleFieldSet.readFrom(bookmarksFile, false, true);
			readBookmarks(MAIN_CATEGORY, simpleFieldSet);
		} catch (MalformedURLException mue1) {
		} catch (IOException ioe1) {
			Logger.error(this, "Error reading the bookmark file (" + bookmarksFile.toString() + "):" + ioe1.getMessage(), ioe1);

			try {
				if (backupBookmarksFile.exists() && backupBookmarksFile.canRead() && backupBookmarksFile.length() > 0) {
					Logger.normal(this, "Attempting to read the backup bookmark file from " + backupBookmarksFile.toString());
					SimpleFieldSet simpleFieldSet = SimpleFieldSet.readFrom(backupBookmarksFile, false, true);
					readBookmarks(MAIN_CATEGORY, simpleFieldSet);
				} else {
					Logger.normal(this, "We couldn't find the backup either! - " + FileUtil.getCanonicalFile(backupBookmarksFile));
					// restore the default bookmark set
					readBookmarks(MAIN_CATEGORY, DEFAULT_BOOKMARKS);
				}
			} catch (IOException ioe2) {
				Logger.error(this, "Error reading the backup bookmark file !" + ioe2.getMessage(), ioe2);
			}
		}
		//populate defaults for hosts without full access permissions if we're in gateway mode.
		if (publicGateway) {
			putPaths("\\", DEFAULT_CATEGORY);
			readBookmarks(DEFAULT_CATEGORY, DEFAULT_BOOKMARKS);
		}
	}

	//
	// ACCESSORS
	//

	/**
	 * Returns the parent path of the given path. A path always ends with a slash.
	 * The parent of the root path is again the root path.
	 *
	 * @param path
	 * 		The path to get the parent for
	 * @return The parent path of the given path
	 */
	public String parentPath(String path) {
		if (path.equals("/")) {
			return "/";
		}

		return path.substring(0, path.substring(0, path.length() - 1).lastIndexOf("/")) + "/";
	}

	/**
	 * Returns the category for the given path.
	 *
	 * @param path
	 * 		The path to get the category for
	 * @return The category for the given path, or {@code null} if the path does
	 *         not specify a category
	 */
	public BookmarkCategory getCategoryByPath(String path) {
		Bookmark category = getBookmarkByPath(path);
		if (category instanceof BookmarkCategory) {
			return (BookmarkCategory) category;
		}

		return null;
	}

	/**
	 * Returns the bookmark for the given path.
	 *
	 * @param path
	 * 		The path to get the bookmark for
	 * @return The bookmark for the given path, or {@code null} if the path does
	 *         not specify a bookmark
	 */
	public BookmarkItem getItemByPath(String path) {
		if (getBookmarkByPath(path) instanceof BookmarkItem) {
			return (BookmarkItem) getBookmarkByPath(path);
		}

		return null;
	}

	//
	// ACTIONS
	//

	/** Re-adds the default bookmarks as a new category in the root path. */
	public void reAddDefaultBookmarks() {
		BookmarkCategory bookmarkCategory = new BookmarkCategory(l10n("defaultBookmarks") + " - " + new Date());
		addBookmark("/", bookmarkCategory);
		_innerReadBookmarks("/", bookmarkCategory, DEFAULT_BOOKMARKS);
	}

	/**
	 * Adds the given bookmark to the given parent path.
	 *
	 * @param parentPath
	 * 		The parent path to add the bookmark to
	 * @param bookmark
	 * 		The bookmark to add
	 */
	public void addBookmark(String parentPath, Bookmark bookmark) {
		if (logMINOR) {
			Logger.minor(this, "Adding bookmark " + bookmark + " to " + parentPath);
		}
		BookmarkCategory parent = getCategoryByPath(parentPath);
		parent.addBookmark(bookmark);
		putPaths(parentPath + bookmark.getName() + ((bookmark instanceof BookmarkCategory) ? "/" : ""), bookmark);

		if (bookmark instanceof BookmarkItem) {
			subscribeToUSK((BookmarkItem) bookmark);
		}
	}

	/**
	 * Renames the bookmark at the given path to the given new name.
	 *
	 * @param path
	 * 		The path to rename
	 * @param newName
	 * 		The new name of the bookmark
	 */
	public void renameBookmark(String path, String newName) {
		Bookmark bookmark = getBookmarkByPath(path);
		String oldName = bookmark.getName();
		String oldPath = '/' + oldName;
		String newPath = path.substring(0, path.indexOf(oldPath)) + '/' + newName + (bookmark instanceof BookmarkCategory ? "/" : "");

		bookmark.setName(newName);
		synchronized (bookmarks) {
			Iterator<String> it = bookmarks.keySet().iterator();
			while (it.hasNext()) {
				String s = it.next();
				if (s.startsWith(path)) {
					it.remove();
				}
			}
			putPaths(newPath, bookmark);
		}
		storeBookmarks();
	}

	/**
	 * Moves the bookmark at the given path to the given new path.
	 *
	 * @param bookmarkPath
	 * 		The path of the bookmark to move
	 * @param newParentPath
	 * 		The new path of the bookmark
	 */
	public void moveBookmark(String bookmarkPath, String newParentPath) {
		Bookmark bookmark = getBookmarkByPath(bookmarkPath);
		addBookmark(newParentPath, bookmark);

		getCategoryByPath(parentPath(bookmarkPath)).removeBookmark(bookmark);
		removePaths(bookmarkPath);
	}

	/**
	 * Moves the bookmark up within its parent path.
	 *
	 * @param path
	 * 		The path of the bookmark to move up
	 * @param store
	 * 		{@code true} to store the bookmarks afterwards, {@code false} to not store
	 * 		the bookmarks afterwards
	 */
	public void moveBookmarkUp(String path, boolean store) {
		BookmarkCategory parent = getCategoryByPath(parentPath(path));
		parent.moveBookmarkUp(getBookmarkByPath(path));

		if (store) {
			storeBookmarks();
		}
	}

	/**
	 * Moves the bookmark down within its parent path.
	 *
	 * @param path
	 * 		The path of the bookmark to move down
	 * @param store
	 * 		{@code true} to store the bookmarks afterwards, {@code false} to not store
	 * 		the bookmarks afterwards
	 */
	public void moveBookmarkDown(String path, boolean store) {
		BookmarkCategory parent = getCategoryByPath(parentPath(path));
		parent.moveBookmarkDown(getBookmarkByPath(path));

		if (store) {
			storeBookmarks();
		}
	}

	/**
	 * Removes the bookmark at the given path.
	 *
	 * @param path
	 * 		The path of the bookmark to remove
	 */
	public void removeBookmark(String path) {
		Bookmark bookmark = getBookmarkByPath(path);
		if (bookmark == null) {
			return;
		}

		if (bookmark instanceof BookmarkCategory) {
			BookmarkCategory cat = (BookmarkCategory) bookmark;
			for (int i = 0; i < cat.size(); i++) {
				removeBookmark(path + cat.get(i).getName() + ((cat.get(i) instanceof BookmarkCategory) ? "/" : ""));
			}
		} else {
			if (((BookmarkItem) bookmark).getKeyType().equals("USK")) {
				try {
					USK u = ((BookmarkItem) bookmark).getUSK();
					if (!wantUSK(u, (BookmarkItem) bookmark)) {
						this.nodeClientCore.uskManager.unsubscribe(u, this.uskUpdatedCallback);
					}
				} catch (MalformedURLException mue) {
				}
			}
		}

		getCategoryByPath(parentPath(path)).removeBookmark(bookmark);
		synchronized (bookmarks) {
			bookmarks.remove(path);
		}
	}

	/**
	 * Stores the bookmarks. Storing the bookmarks works by first writing the
	 * bookmarks to the backup file and renaming the backup file to the real
	 * filename once finished
	 */
	public void storeBookmarks() {
		Logger.normal(this, "Attempting to save bookmarks to " + bookmarksFile.toString());
		SimpleFieldSet simpleFieldSet = null;
		synchronized (bookmarks) {
			if (savingBookmarks) {
				return;
			}
			savingBookmarks = true;

			simpleFieldSet = toSimpleFieldSet();
		}
		FileOutputStream fileOutputStream = null;
		try {
			fileOutputStream = new FileOutputStream(backupBookmarksFile);
			simpleFieldSet.writeToBigBuffer(fileOutputStream);
			if (!FileUtil.renameTo(backupBookmarksFile, bookmarksFile)) {
				Logger.error(this, "Unable to rename " + backupBookmarksFile.toString() + " to " + bookmarksFile.toString());
			}
		} catch (IOException ioe1) {
			Logger.error(this, "An error has occured saving the bookmark file :" + ioe1.getMessage(), ioe1);
		} finally {
			Closer.close(fileOutputStream);

			synchronized (bookmarks) {
				savingBookmarks = false;
			}
		}
	}

	//
	// REQUESTCLIENT METHODS
	//

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public void removeFrom(ObjectContainer container) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

	//
	// STATIC METHODS
	//

	/**
	 * Creates a simple field set from the given bookmark category.
	 *
	 * @param bookmarkCategory
	 * 		The bookmark category to serialize
	 * @return The simple field set containing the bookmark category
	 */
	public static SimpleFieldSet toSimpleFieldSet(BookmarkCategory bookmarkCategory) {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		List<BookmarkCategory> subCategories = bookmarkCategory.getSubCategories();

		for (int index = 0; index < subCategories.size(); index++) {
			BookmarkCategory currentCat = subCategories.get(index);
			simpleFieldSet.put(BOOKMARK_CATEGORY_NAME + index, currentCat.getSimpleFieldSet());
		}
		simpleFieldSet.put(BOOKMARK_CATEGORY_NAME, subCategories.size());

		List<BookmarkItem> bookmarkItems = bookmarkCategory.getItems();
		for (int i = 0; i < bookmarkItems.size(); i++) {
			simpleFieldSet.put(BOOKMARK_NAME + i, bookmarkItems.get(i).getSimpleFieldSet());
		}
		simpleFieldSet.put(BOOKMARK_NAME, bookmarkItems.size());

		return simpleFieldSet;
	}

	//
	// PRIVATE METHODS
	//

	/**
	 * Returns the translation for the given key, prepended by “BookmarkManager.”
	 *
	 * @param key
	 * 		The key to retrieve the translation for
	 * @return The translated value
	 */
	private static String l10n(String key) {
		return NodeL10n.getBase().getString("BookmarkManager." + key);
	}

	/**
	 * Returns the bookmark at the given path.
	 *
	 * @param path
	 * 		The path of the bookmark
	 * @return The bookmark, or {@code null} if a bookmark could not be found at
	 *         the given path
	 */
	private Bookmark getBookmarkByPath(String path) {
		synchronized (bookmarks) {
			return bookmarks.get(path);
		}
	}

	/**
	 * Checks if the given USK is contained in any bookmark but the given one.
	 *
	 * @param usk
	 * 		The USK to check for
	 * @param ignore
	 * 		The bookmark to ignore
	 * @return {@code true} if any other bookmark than the given one contains the
	 *         given USK, {@code false} otherwise
	 */
	private boolean wantUSK(USK usk, BookmarkItem ignore) {
		List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
		for (BookmarkItem item : items) {
			if (item == ignore) {
				continue;
			}
			if (!"USK".equals(item.getKeyType())) {
				continue;
			}

			try {
				FreenetURI freenetUri = item.getURI();
				USK bookmarkUsk = USK.create(freenetUri);

				if (bookmarkUsk.equals(usk, false)) {
					return true;
				}
			} catch (MalformedURLException mue1) {
			}
		}
		return false;
	}

	/**
	 * Recursively adds the given bookmark and all its contained bookmarks and
	 * categories under the given path.
	 *
	 * @param path
	 * 		The path to add the bookmark at
	 * @param bookmark
	 * 		The bookmark to add
	 */
	private void putPaths(String path, Bookmark bookmark) {
		synchronized (bookmarks) {
			bookmarks.put(path, bookmark);
		}
		if (bookmark instanceof BookmarkCategory) {
			for (int i = 0; i < ((BookmarkCategory) bookmark).size(); i++) {
				Bookmark child = ((BookmarkCategory) bookmark).get(i);
				putPaths(path + child.getName() + (child instanceof BookmarkItem ? "" : "/"), child);
			}
		}

	}

	/**
	 * Removes the given path and paths beneath it from the bookmarks.
	 *
	 * @param path
	 * 		The path to remove
	 */
	private void removePaths(String path) {
		if (getBookmarkByPath(path) instanceof BookmarkCategory) {
			BookmarkCategory cat = getCategoryByPath(path);
			for (int i = 0; i < cat.size(); i++) {
				removePaths(path + cat.get(i).getName() + (cat.get(i) instanceof BookmarkCategory ? "/" : ""));
			}
		}
		bookmarks.remove(path);
	}

	/** Stores the bookmarks lazily, i.e. a job is queued to store the bookmarks. */
	private void storeBookmarksLazy() {
		synchronized (bookmarks) {
			if (savingBookmarksLazy) {
				return;
			}
			savingBookmarksLazy = true;
			nodeClientCore.node.ticker.queueTimedJob(new Runnable() {

				@Override
				public void run() {
					try {
						storeBookmarks();
					} finally {
						savingBookmarksLazy = false;
					}
				}

			}, MINUTES.toMillis(5));
		}
	}

	/**
	 * Reads the bookmarks from the given fieldset into the given category.
	 *
	 * @param category
	 * 		The category to read the bookmarks into
	 * @param simpleFieldSet
	 * 		The simple field set to parse the bookmarks from
	 */
	private void readBookmarks(BookmarkCategory category, SimpleFieldSet simpleFieldSet) {
		_innerReadBookmarks("", category, simpleFieldSet);
	}

	/**
	 * Subscribes to the USK of the given bookmark if the key of the bookmark is a
	 * USK.
	 *
	 * @param bookmarkItem
	 * 		The bookmark to which to subscribe to
	 */
	private void subscribeToUSK(BookmarkItem bookmarkItem) {
		if ("USK".equals(bookmarkItem.getKeyType())) {
			try {
				USK usk = bookmarkItem.getUSK();
				this.nodeClientCore.uskManager.subscribe(usk, this.uskUpdatedCallback, true, this);
			} catch (MalformedURLException mue) {
			}
		}
	}

	/**
	 * Reads the bookmarks from the given simple field set and stores them in the
	 * given category and under names that have the given prefix prepended.
	 *
	 * @param prefix
	 * 		The prefix for the path names
	 * @param category
	 * 		The category to load the bookmarks into
	 * @param simpleFieldSet
	 * 		The simple field set from which to parse the bookmarks
	 */
	private synchronized void _innerReadBookmarks(String prefix, BookmarkCategory category, SimpleFieldSet simpleFieldSet) {
		boolean hasBeenParsedWithoutAnyProblem = true;
		boolean isRoot = ("".equals(prefix) && MAIN_CATEGORY.equals(category));
		synchronized (bookmarks) {
			if (!isRoot) {
				putPaths(prefix + category.getName() + '/', category);
			}

			try {
				int bookmarkCount = simpleFieldSet.getInt(BOOKMARK_NAME);
				int categoryCount = simpleFieldSet.getInt(BOOKMARK_CATEGORY_NAME);

				for (int bookmarkIndex = 0; bookmarkIndex < bookmarkCount; bookmarkIndex++) {
					SimpleFieldSet subset = simpleFieldSet.getSubset(BOOKMARK_NAME + bookmarkIndex);
					try {
						BookmarkItem bookmarkItem = new BookmarkItem(subset, nodeClientCore.alerts);
						String name = (isRoot ? "" : prefix + category.getName()) + '/' + bookmarkItem.getName();
						putPaths(name, bookmarkItem);
						category.addBookmark(bookmarkItem);
						subscribeToUSK(bookmarkItem);
					} catch (MalformedURLException e) {
						throw new FSParseException(e);
					}
				}

				for (int categoryIndex = 0; categoryIndex < categoryCount; categoryIndex++) {
					SimpleFieldSet subset = simpleFieldSet.getSubset(BOOKMARK_CATEGORY_NAME + categoryIndex);
					BookmarkCategory currentCategory = new BookmarkCategory(subset);
					category.addBookmark(currentCategory);
					String name = (isRoot ? "/" : (prefix + category.getName() + '/'));
					_innerReadBookmarks(name, currentCategory, subset.getSubset("Content"));
				}

			} catch (FSParseException fspe1) {
				Logger.error(this, "Error parsing the bookmarks file!", fspe1);
				hasBeenParsedWithoutAnyProblem = false;
			}

		}
		if (hasBeenParsedWithoutAnyProblem) {
			storeBookmarks();
		}
	}

	/**
	 * Creates a simple field set containing all bookmarks.
	 *
	 * @return A simple field set containing all bookmarks
	 */
	private SimpleFieldSet toSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);

		simpleFieldSet.put("Version", 1);
		synchronized (bookmarks) {
			simpleFieldSet.putAllOverwrite(BookmarkManager.toSimpleFieldSet(MAIN_CATEGORY));
		}

		return simpleFieldSet;
	}

	/**
	 * Callback for the subscribed bookmarks.
	 *
	 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
	 *         (after refactoring)
	 */
	private class USKUpdatedCallback implements USKCallback {

		//
		// USKCALLBACK METHODS
		//

		@Override
		public void onFoundEdition(long edition, USK key, ObjectContainer container, ClientContext context, boolean wasMetadata, short codec, byte[] data, boolean newKnownGood, boolean newSlotToo) {
			if (!newKnownGood) {
				FreenetURI uri = key.copy(edition).getURI();
				nodeClientCore.makeClient(PRIORITY_PROGRESS, false, false).prefetch(uri, MINUTES.toMillis(60), FProxyToadlet.MAX_LENGTH_WITH_PROGRESS, null, PRIORITY_PROGRESS);
				return;
			}
			List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
			boolean matched = false;
			boolean updated = false;
			for (BookmarkItem bookmarkItem : items) {
				if (!"USK".equals(bookmarkItem.getKeyType())) {
					continue;
				}

				try {
					FreenetURI furi = bookmarkItem.getURI();
					USK usk = USK.create(furi);

					if (usk.equals(key, false)) {
						if (logMINOR) {
							Logger.minor(this, "Updating bookmark for " + furi + " to edition " + edition);
						}
						matched = true;
						updated |= bookmarkItem.setEdition(edition, nodeClientCore);
						// We may have bookmarked the same site twice, so continue the search.
					}
				} catch (MalformedURLException mue1) {
				}
			}
			if (updated) {
				storeBookmarksLazy();
			} else if (!matched) {
				Logger.error(this, "No match for bookmark " + key + " edition " + edition);
			}
		}

		@Override
		public short getPollingPriorityNormal() {
			return PRIORITY;
		}

		@Override
		public short getPollingPriorityProgress() {
			return PRIORITY_PROGRESS;
		}

	}

}
