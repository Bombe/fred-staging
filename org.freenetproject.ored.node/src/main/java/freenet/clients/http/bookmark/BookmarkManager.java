/*
 * Copyright 1999-2022 The Freenet Project
 * Copyright 2022 Marine Master
 *
 * This file is part of Oldenet.
 *
 * Oldenet is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or any later version.
 *
 * Oldenet is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with Oldenet.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package freenet.clients.http.bookmark;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.TimeUnit;

import freenet.client.async.ClientContext;
import freenet.client.async.USKCallback;
import freenet.client.request.PriorityClasses;
import freenet.client.request.RequestClient;
import freenet.clients.http.FProxyToadlet;
import freenet.keys.FreenetURI;
import freenet.keys.USK;
import freenet.l10n.NodeL10n;
import freenet.node.NodeClientCore;
import freenet.nodelogger.Logger;
import freenet.support.LogThresholdCallback;
import freenet.support.Logger.LogLevel;
import freenet.support.SimpleFieldSet;
import freenet.support.io.Closer;
import freenet.support.io.FileUtil;
import freenet.support.node.FSParseException;
import freenet.support.node.SemiOrderedShutdownHook;

public class BookmarkManager implements RequestClient {

	public static final SimpleFieldSet DEFAULT_BOOKMARKS;

	private final NodeClientCore node;

	private final USKUpdatedCallback uskCB = new USKUpdatedCallback();

	public static final BookmarkCategory MAIN_CATEGORY = new BookmarkCategory("/");

	public static final BookmarkCategory DEFAULT_CATEGORY = new BookmarkCategory("\\");

	private final HashMap<String, Bookmark> bookmarks = new HashMap<>();

	private final File bookmarksFile;

	private final File backupBookmarksFile;

	private boolean isSavingBookmarks = false;

	private boolean isSavingBookmarksLazy = false;

	static {
		String name = "/staticfiles/defaultbookmarks.dat";
		SimpleFieldSet defaultBookmarks = null;
		try {
			try (InputStream in = BookmarkManager.class.getResourceAsStream(name)) {
				// loader returns null on lookup failures:
				if (in != null) {
					defaultBookmarks = SimpleFieldSet.readFrom(in, false, false);
				}
			}
		}
		catch (Exception ex) {
			Logger.error(BookmarkManager.class,
					"Error while loading the default bookmark file from " + name + " :" + ex.getMessage(), ex);
		}
		finally {
			DEFAULT_BOOKMARKS = defaultBookmarks;
		}
	}

	private static volatile boolean logMINOR;

	static {
		Logger.registerLogThresholdCallback(new LogThresholdCallback() {
			@Override
			public void shouldUpdate() {
				logMINOR = Logger.shouldLog(LogLevel.MINOR, this);
			}
		});
	}

	public BookmarkManager(NodeClientCore n, boolean publicGateway) {
		this.putPaths("/", MAIN_CATEGORY);
		this.node = n;
		this.bookmarksFile = n.node.userDir().file("bookmarks.dat");
		this.backupBookmarksFile = n.node.userDir().file("bookmarks.dat.bak");

		try {
			// Read the backup file if necessary
			if (!this.bookmarksFile.exists() || this.bookmarksFile.length() == 0) {
				throw new IOException();
			}
			Logger.normal(this, "Attempting to read the bookmark file from " + this.bookmarksFile);
			SimpleFieldSet sfs = SimpleFieldSet.readFrom(this.bookmarksFile, false, true);
			this.readBookmarks(MAIN_CATEGORY, sfs);
		}
		catch (MalformedURLException ignored) {
		}
		catch (IOException ioe) {
			Logger.error(this, "Error reading the bookmark file (" + this.bookmarksFile + "):" + ioe.getMessage(), ioe);

			try {
				if (this.backupBookmarksFile.exists() && this.backupBookmarksFile.canRead()
						&& this.backupBookmarksFile.length() > 0) {
					Logger.normal(this, "Attempting to read the backup bookmark file from " + this.backupBookmarksFile);
					SimpleFieldSet sfs = SimpleFieldSet.readFrom(this.backupBookmarksFile, false, true);
					this.readBookmarks(MAIN_CATEGORY, sfs);
				}
				else {
					Logger.normal(this, "We couldn't find the backup either! - "
							+ FileUtil.getCanonicalFile(this.backupBookmarksFile));
					// restore the default bookmark set
					this.readBookmarks(MAIN_CATEGORY, DEFAULT_BOOKMARKS);
				}
			}
			catch (IOException ex) {
				Logger.error(this, "Error reading the backup bookmark file !" + ex.getMessage(), ex);
			}
		}
		// populate defaults for hosts without full access permissions if we're in gateway
		// mode.
		if (publicGateway) {
			this.putPaths("\\", DEFAULT_CATEGORY);
			this.readBookmarks(DEFAULT_CATEGORY, DEFAULT_BOOKMARKS);
		}

		SemiOrderedShutdownHook.get().addEarlyJob(new Thread() {
			BookmarkManager bm = BookmarkManager.this;

			@Override
			public void run() {
				this.bm.storeBookmarks();
				this.bm = null;
			}
		});
	}

	public void reAddDefaultBookmarks() {
		BookmarkCategory bc = new BookmarkCategory(this.l10n("defaultBookmarks") + " - " + new Date());
		this.addBookmark("/", bc);
		this._innerReadBookmarks("/", bc, DEFAULT_BOOKMARKS);
	}

	public String l10n(String key) {
		return NodeL10n.getBase().getString("BookmarkManager." + key);
	}

	public String parentPath(String path) {
		if (path.equals("/")) {
			return "/";
		}

		return path.substring(0, path.substring(0, path.length() - 1).lastIndexOf('/')) + "/";
	}

	public Bookmark getBookmarkByPath(String path) {
		synchronized (this.bookmarks) {
			return this.bookmarks.get(path);
		}
	}

	public BookmarkCategory getCategoryByPath(String path) {
		Bookmark cat = this.getBookmarkByPath(path);
		if (cat instanceof BookmarkCategory) {
			return (BookmarkCategory) cat;
		}

		return null;
	}

	public BookmarkItem getItemByPath(String path) {
		if (this.getBookmarkByPath(path) instanceof BookmarkItem) {
			return (BookmarkItem) this.getBookmarkByPath(path);
		}

		return null;
	}

	public void addBookmark(String parentPath, Bookmark bookmark) {
		if (logMINOR) {
			Logger.minor(this, "Adding bookmark " + bookmark + " to " + parentPath);
		}
		BookmarkCategory parent = this.getCategoryByPath(parentPath);
		parent.addBookmark(bookmark);
		this.putPaths(parentPath + bookmark.getName() + ((bookmark instanceof BookmarkCategory) ? "/" : ""), bookmark);

		if (bookmark instanceof BookmarkItem) {
			this.subscribeToUSK((BookmarkItem) bookmark);
		}
	}

	public void renameBookmark(String path, String newName) {
		Bookmark bookmark = this.getBookmarkByPath(path);
		String oldName = bookmark.getName();
		String oldPath = '/' + oldName;
		String newPath = path.substring(0, path.indexOf(oldPath)) + '/' + newName
				+ ((bookmark instanceof BookmarkCategory) ? "/" : "");

		bookmark.setName(newName);
		synchronized (this.bookmarks) {
			this.bookmarks.keySet().removeIf(s -> s.startsWith(path));
			this.putPaths(newPath, bookmark);
		}
		this.storeBookmarks();
	}

	public void moveBookmark(String bookmarkPath, String newParentPath) {
		Bookmark b = this.getBookmarkByPath(bookmarkPath);
		this.addBookmark(newParentPath, b);

		this.getCategoryByPath(this.parentPath(bookmarkPath)).removeBookmark(b);
		this.removePaths(bookmarkPath);
	}

	public void removeBookmark(String path) {
		Bookmark bookmark = this.getBookmarkByPath(path);
		if (bookmark == null) {
			return;
		}

		if (bookmark instanceof BookmarkCategory cat) {
			for (int i = 0; i < cat.size(); i++) {
				this.removeBookmark(
						path + cat.get(i).getName() + ((cat.get(i) instanceof BookmarkCategory) ? "/" : ""));
			}
		}
		else {
			if (((BookmarkItem) bookmark).getKeyType().equals("USK")) {
				try {
					USK u = ((BookmarkItem) bookmark).getUSK();
					if (!this.wantUSK(u, (BookmarkItem) bookmark)) {
						this.node.uskManager.unsubscribe(u, this.uskCB);
					}
				}
				catch (MalformedURLException ignored) {
				}
			}
		}

		this.getCategoryByPath(this.parentPath(path)).removeBookmark(bookmark);
		synchronized (this.bookmarks) {
			this.bookmarks.remove(path);
		}
	}

	private boolean wantUSK(USK u, BookmarkItem ignore) {
		List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
		for (BookmarkItem item : items) {
			if (item == ignore) {
				continue;
			}
			if (!"USK".equals(item.getKeyType())) {
				continue;
			}

			try {
				FreenetURI furi = new FreenetURI(item.getKey());
				USK usk = USK.create(furi);

				if (usk.equals(u, false)) {
					return true;
				}
			}
			catch (MalformedURLException ignored) {
			}
		}
		return false;
	}

	public void moveBookmarkUp(String path, boolean store) {
		BookmarkCategory parent = this.getCategoryByPath(this.parentPath(path));
		parent.moveBookmarkUp(this.getBookmarkByPath(path));

		if (store) {
			this.storeBookmarks();
		}
	}

	public void moveBookmarkDown(String path, boolean store) {
		BookmarkCategory parent = this.getCategoryByPath(this.parentPath(path));
		parent.moveBookmarkDown(this.getBookmarkByPath(path));

		if (store) {
			this.storeBookmarks();
		}
	}

	private void putPaths(String path, Bookmark b) {
		synchronized (this.bookmarks) {
			this.bookmarks.put(path, b);
		}
		if (b instanceof BookmarkCategory) {
			for (int i = 0; i < ((BookmarkCategory) b).size(); i++) {
				Bookmark child = ((BookmarkCategory) b).get(i);
				this.putPaths(path + child.getName() + ((child instanceof BookmarkItem) ? "" : "/"), child);
			}
		}

	}

	private void removePaths(String path) {
		if (this.getBookmarkByPath(path) instanceof BookmarkCategory) {
			BookmarkCategory cat = this.getCategoryByPath(path);
			for (int i = 0; i < cat.size(); i++) {
				this.removePaths(path + cat.get(i).getName() + ((cat.get(i) instanceof BookmarkCategory) ? "/" : ""));
			}
		}
		this.bookmarks.remove(path);
	}

	public FreenetURI[] getBookmarkURIs() {
		List<BookmarkItem> items = MAIN_CATEGORY.getAllItems();
		FreenetURI[] uris = new FreenetURI[items.size()];
		for (int i = 0; i < items.size(); i++) {
			uris[i] = items.get(i).getURI();
		}

		return uris;
	}

	public void storeBookmarksLazy() {
		synchronized (this.bookmarks) {
			if (this.isSavingBookmarksLazy) {
				return;
			}
			this.isSavingBookmarksLazy = true;
			this.node.node.ticker.queueTimedJob(() -> {
				try {
					BookmarkManager.this.storeBookmarks();
				}
				finally {
					BookmarkManager.this.isSavingBookmarksLazy = false;
				}
			}, TimeUnit.MINUTES.toMillis(5));
		}
	}

	public void storeBookmarks() {
		Logger.normal(this, "Attempting to save bookmarks to " + this.bookmarksFile.toString());
		SimpleFieldSet sfs;
		synchronized (this.bookmarks) {
			if (this.isSavingBookmarks) {
				return;
			}
			this.isSavingBookmarks = true;

			sfs = this.toSimpleFieldSet();
		}
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(this.backupBookmarksFile);
			sfs.writeToBigBuffer(fos);
			fos.close();
			fos = null;
			if (!FileUtil.renameTo(this.backupBookmarksFile, this.bookmarksFile)) {
				Logger.error(this, "Unable to rename " + this.backupBookmarksFile + " to " + this.bookmarksFile);
			}
		}
		catch (IOException ioe) {
			Logger.error(this, "An error has occured saving the bookmark file :" + ioe.getMessage(), ioe);
		}
		finally {
			Closer.close(fos);
			synchronized (this.bookmarks) {
				this.isSavingBookmarks = false;
			}
		}
	}

	private void readBookmarks(BookmarkCategory category, SimpleFieldSet sfs) {
		this._innerReadBookmarks("", category, sfs);
	}

	static final short PRIORITY = PriorityClasses.BULK_SPLITFILE_PRIORITY_CLASS;
	static final short PRIORITY_PROGRESS = PriorityClasses.UPDATE_PRIORITY_CLASS;

	private void subscribeToUSK(BookmarkItem item) {
		if ("USK".equals(item.getKeyType())) {
			try {
				USK u = item.getUSK();
				this.node.uskManager.subscribe(u, this.uskCB, true, this);
			}
			catch (MalformedURLException ignored) {
			}
		}
	}

	private synchronized void _innerReadBookmarks(String prefix, BookmarkCategory category, SimpleFieldSet sfs) {
		boolean hasBeenParsedWithoutAnyProblem = true;
		boolean isRoot = ("".equals(prefix) && MAIN_CATEGORY.equals(category));
		synchronized (this.bookmarks) {
			if (!isRoot) {
				this.putPaths(prefix + category.name + '/', category);
			}

			if (sfs == null) {
				hasBeenParsedWithoutAnyProblem = false;
			}
			else {
				try {
					int nbBookmarks = sfs.getInt(BookmarkItem.NAME);
					int nbCategories = sfs.getInt(BookmarkCategory.NAME);

					for (int i = 0; i < nbBookmarks; i++) {
						SimpleFieldSet subset = sfs.getSubset(BookmarkItem.NAME + i);
						try {
							BookmarkItem item = new BookmarkItem(subset, this, this.node.alerts);
							String name = (isRoot ? "" : prefix + category.name) + '/' + item.name;
							this.putPaths(name, item);
							category.addBookmark(item);
							item.registerUserAlert();
							this.subscribeToUSK(item);
						}
						catch (MalformedURLException ex) {
							throw new FSParseException(ex);
						}
					}

					for (int i = 0; i < nbCategories; i++) {
						SimpleFieldSet subset = sfs.getSubset(BookmarkCategory.NAME + i);
						BookmarkCategory currentCategory = new BookmarkCategory(subset);
						category.addBookmark(currentCategory);
						String name = (isRoot ? "/" : (prefix + category.name + '/'));
						this._innerReadBookmarks(name, currentCategory, subset.getSubset("Content"));
					}

				}
				catch (FSParseException ex) {
					Logger.error(this, "Error parsing the bookmarks file!", ex);
					hasBeenParsedWithoutAnyProblem = false;
				}
			}

		}
		if (hasBeenParsedWithoutAnyProblem) {
			this.storeBookmarks();
		}
	}

	public SimpleFieldSet toSimpleFieldSet() {
		SimpleFieldSet sfs = new SimpleFieldSet(true);

		sfs.put("Version", 1);
		synchronized (this.bookmarks) {
			sfs.putAllOverwrite(BookmarkManager.toSimpleFieldSet(MAIN_CATEGORY));
		}

		return sfs;
	}

	public static SimpleFieldSet toSimpleFieldSet(BookmarkCategory cat) {
		SimpleFieldSet sfs = new SimpleFieldSet(true);
		List<BookmarkCategory> bc = cat.getSubCategories();

		for (int i = 0; i < bc.size(); i++) {
			BookmarkCategory currentCat = bc.get(i);
			sfs.put(BookmarkCategory.NAME + i, currentCat.getSimpleFieldSet());
		}
		sfs.put(BookmarkCategory.NAME, bc.size());

		List<BookmarkItem> bi = cat.getItems();
		for (int i = 0; i < bi.size(); i++) {
			sfs.put(BookmarkItem.NAME + i, bi.get(i).getSimpleFieldSet());
		}
		sfs.put(BookmarkItem.NAME, bi.size());

		return sfs;
	}

	@Override
	public boolean persistent() {
		return false;
	}

	@Override
	public boolean realTimeFlag() {
		return false;
	}

	private class USKUpdatedCallback implements USKCallback {

		@Override
		public void onFoundEdition(long edition, USK key, ClientContext context, boolean wasMetadata, short codec,
				byte[] data, boolean newKnownGood, boolean newSlotToo) {
			if (!newKnownGood) {
				FreenetURI uri = key.copy(edition).getURI();
				BookmarkManager.this.node.makeClient(PRIORITY_PROGRESS, false, false).prefetch(uri,
						TimeUnit.MINUTES.toMillis(60), FProxyToadlet.MAX_LENGTH_WITH_PROGRESS, null, PRIORITY_PROGRESS);
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
					FreenetURI furi = new FreenetURI(bookmarkItem.getKey());
					USK usk = USK.create(furi);

					if (usk.equals(key, false)) {
						if (logMINOR) {
							Logger.minor(this, "Updating bookmark for " + furi + " to edition " + edition);
						}
						matched = true;
						updated |= bookmarkItem.setEdition(edition, BookmarkManager.this.node);
						// We may have bookmarked the same site twice, so continue the
						// search.
					}
				}
				catch (MalformedURLException ignored) {
				}
			}
			if (updated) {
				BookmarkManager.this.storeBookmarksLazy();
			}
			else if (!matched) {
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
