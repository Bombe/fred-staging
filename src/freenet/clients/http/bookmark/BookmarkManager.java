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

	public static final BookmarkCategory MAIN_CATEGORY = new BookmarkCategory("/");

	public static final BookmarkCategory DEFAULT_CATEGORY = new BookmarkCategory("\\");

	private static final short PRIORITY = RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS;

	private static final short PRIORITY_PROGRESS = RequestStarter.UPDATE_PRIORITY_CLASS;

	/** Name for bookmarks in simple field set serialization. */
	private static final String BOOKMARK_NAME = "Bookmark";

	/** Name for bookmark categories in simple field set serialization. */
	private static final String BOOKMARK_CATEGORY_NAME = "BookmarkCategory";

	private final NodeClientCore nodeClientCore;

	private final USKUpdatedCallback uskUpdatedCallback = new USKUpdatedCallback();

	private final Map<String, Bookmark> bookmarks = new HashMap<String, Bookmark>();

	private final File bookmarksFile;

	private final File backupBookmarksFile;

	private boolean savingBookmarks = false;

	private boolean savingBookmarksLazy = false;

	public BookmarkManager(NodeClientCore nodeClientCore, boolean publicGateway) {
		putPaths("/", MAIN_CATEGORY);
		this.nodeClientCore = nodeClientCore;
		this.bookmarksFile = nodeClientCore.node.userDir().file("bookmarks.dat");
		this.backupBookmarksFile = nodeClientCore.node.userDir().file("bookmarks.dat.bak");

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

	public String parentPath(String path) {
		if (path.equals("/")) {
			return "/";
		}

		return path.substring(0, path.substring(0, path.length() - 1).lastIndexOf("/")) + "/";
	}

	public BookmarkCategory getCategoryByPath(String path) {
		Bookmark category = getBookmarkByPath(path);
		if (category instanceof BookmarkCategory) {
			return (BookmarkCategory) category;
		}

		return null;
	}

	public BookmarkItem getItemByPath(String path) {
		if (getBookmarkByPath(path) instanceof BookmarkItem) {
			return (BookmarkItem) getBookmarkByPath(path);
		}

		return null;
	}

	//
	// ACTIONS
	//

	public void reAddDefaultBookmarks() {
		BookmarkCategory bookmarkCategory = new BookmarkCategory(l10n("defaultBookmarks") + " - " + new Date());
		addBookmark("/", bookmarkCategory);
		_innerReadBookmarks("/", bookmarkCategory, DEFAULT_BOOKMARKS);
	}

	public void addBookmark(String parentPath, Bookmark bookmark) {
		if (logMINOR) {
			Logger.minor(this, "Adding bookmark " + bookmark + " to " + parentPath);
		}
		BookmarkCategory parent = getCategoryByPath(parentPath);
		parent.addBookmark(bookmark);
		putPaths(parentPath + bookmark.getName() + ((bookmark instanceof BookmarkCategory) ? "/" : ""),
						bookmark);

		if (bookmark instanceof BookmarkItem) {
			subscribeToUSK((BookmarkItem) bookmark);
		}
	}

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

	public void moveBookmark(String bookmarkPath, String newParentPath) {
		Bookmark bookmark = getBookmarkByPath(bookmarkPath);
		addBookmark(newParentPath, bookmark);

		getCategoryByPath(parentPath(bookmarkPath)).removeBookmark(bookmark);
		removePaths(bookmarkPath);
	}

	public void moveBookmarkUp(String path, boolean store) {
		BookmarkCategory parent = getCategoryByPath(parentPath(path));
		parent.moveBookmarkUp(getBookmarkByPath(path));

		if (store) {
			storeBookmarks();
		}
	}

	public void moveBookmarkDown(String path, boolean store) {
		BookmarkCategory parent = getCategoryByPath(parentPath(path));
		parent.moveBookmarkDown(getBookmarkByPath(path));

		if (store) {
			storeBookmarks();
		}
	}

	public void removeBookmark(String path) {
		Bookmark bookmark = getBookmarkByPath(path);
		if (bookmark == null) {
			return;
		}

		if (bookmark instanceof BookmarkCategory) {
			BookmarkCategory cat = (BookmarkCategory) bookmark;
			for (int i = 0; i < cat.size(); i++) {
				removeBookmark(path + cat.get(i).getName() + ((cat.get(i) instanceof BookmarkCategory) ? "/"
																	  : ""));
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

	private static String l10n(String key) {
		return NodeL10n.getBase().getString("BookmarkManager." + key);
	}

	private Bookmark getBookmarkByPath(String path) {
		synchronized (bookmarks) {
			return bookmarks.get(path);
		}
	}

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

	private void removePaths(String path) {
		if (getBookmarkByPath(path) instanceof BookmarkCategory) {
			BookmarkCategory cat = getCategoryByPath(path);
			for (int i = 0; i < cat.size(); i++) {
				removePaths(path + cat.get(i).getName() + (cat.get(i) instanceof BookmarkCategory ? "/" : ""));
			}
		}
		bookmarks.remove(path);
	}

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

	private void readBookmarks(BookmarkCategory category, SimpleFieldSet simpleFieldSet) {
		_innerReadBookmarks("", category, simpleFieldSet);
	}

	private void subscribeToUSK(BookmarkItem bookmarkItem) {
		if ("USK".equals(bookmarkItem.getKeyType())) {
			try {
				USK usk = bookmarkItem.getUSK();
				this.nodeClientCore.uskManager.subscribe(usk, this.uskUpdatedCallback, true, this);
			} catch (MalformedURLException mue) {
			}
		}
	}

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

	private SimpleFieldSet toSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);

		simpleFieldSet.put("Version", 1);
		synchronized (bookmarks) {
			simpleFieldSet.putAllOverwrite(BookmarkManager.toSimpleFieldSet(MAIN_CATEGORY));
		}

		return simpleFieldSet;
	}

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
