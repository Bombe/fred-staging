/*
 * fred - BookmarkManagerTest.java - Copyright © 2013 David Roden
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package freenet.clients.http.bookmark;

import static freenet.clients.http.bookmark.BookmarkManager.parentPath;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import freenet.client.async.USKManager;
import freenet.keys.FreenetURI;
import freenet.node.NodeClientCore;
import freenet.node.useralerts.UserAlertManager;

import junit.framework.TestCase;

/**
 * Tests for {@link BookmarkManager}.
 * <p/>
 * Most of the tests use {@link #findBookmark(BookmarkManager, Position,
 * Bookmark...)} and {@link #findBookmarkCategory(BookmarkManager, Position,
 * Bookmark...)} to find a random {@link BookmarkItem} or {@link
 * BookmarkCategory} from the default bookmarks.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class BookmarkManagerTest extends TestCase {

	/**
	 * Position for wanted bookmarks relative to their parent categories.
	 *
	 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
	 */
	private enum Position {

		/** Any position is fine. */
		ANY,

		/** Only first items/categories, please. */
		FIRST,

		/** Everything but the first items/categories. */
		NOT_FIRST,

		/** Onyl the last items/categories. */
		LAST,

		/** Everything but the last items/categories. */
		NOT_LAST

	}

	//
	// TEST METHODS
	//

	/**
	 * Tests that the {@link BookmarkManager} loads a default set of bookmarks if
	 * it can not load its bookmark files.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testBookmarkManagerLoadsDefaultBookmarks() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		assertNotNull("main category", bookmarkManager.getBookmarks());
		assertTrue("main category has sub categories", bookmarkManager.getBookmarks().getSubCategories().size() > 0);
		assertTrue("main category has items", bookmarkManager.getBookmarks().getAllItems().size() > 0);
	}

	/**
	 * Tests that an added bookmark can afterwards be located in the category it
	 * was added to.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testAddBookmark() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		UserAlertManager userAlertManager = mock(UserAlertManager.class);
		BookmarkContainer parentCategory = findBookmarkCategory(bookmarkManager, Position.ANY);
		BookmarkItem newItem = new BookmarkItem(new FreenetURI("KSK@foo"), "foo", "foo", "foo (short)", true, userAlertManager);
		bookmarkManager.addBookmark(parentCategory.getPath(), newItem);
		assertTrue("new position", positionOfBookmark(bookmarkManager, parentCategory.getPath(), newItem) > -1);
	}

	/**
	 * Tests that an added bookmark category can afterwards be located in the
	 * category it was added to.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testAddBookmarkCategory() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer parentCategory = findBookmarkCategory(bookmarkManager, Position.ANY);
		BookmarkCategory newCategory = new BookmarkCategory("Test Category");
		bookmarkManager.addBookmark(parentCategory.getPath(), newCategory);
		assertTrue("new position", positionOfBookmarkCategory(bookmarkManager, parentCategory.getPath(), newCategory) > -1);
	}

	/**
	 * Tests that a bookmark is deleted by checking that it is not present anymore
	 * in the parent category after deleting it.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testDeleteBookmarks() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer bookmarkContainer = findBookmark(bookmarkManager, Position.ANY);
		bookmarkManager.removeBookmark(bookmarkContainer.getPath());
		assertEquals("new position", -1, positionOfBookmark(bookmarkManager, bookmarkContainer));
	}

	/**
	 * Tests that a bookmark category is deleted by checking that it is not present
	 * anymore in the parent category after deleting it.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testDeleteBookmarkCategory() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer categoryContainer = findBookmarkCategory(bookmarkManager, Position.ANY);
		bookmarkManager.removeBookmark(categoryContainer.getPath());
		assertEquals("new position", -1, positionOfBookmarkCategory(bookmarkManager, categoryContainer));
	}

	/**
	 * Tests that a bookmark is moved up correctly by verifying the position after
	 * moving it.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testMoveBookmarkUp() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer bookmark = findBookmark(bookmarkManager, Position.NOT_FIRST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(bookmark.getPath())).getItems().indexOf(bookmark.getBookmark());
		bookmarkManager.moveBookmarkUp(bookmark.getPath(), false);
		assertEquals("new position", currentPosition - 1, positionOfBookmark(bookmarkManager, bookmark));
	}

	/**
	 * Tests that a bookmark is not moved up when it is the first bookmark in its
	 * parent category.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testDoNotMoveFirstBookmarkUp() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer bookmark = findBookmark(bookmarkManager, Position.FIRST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(bookmark.getPath())).getItems().indexOf(bookmark.getBookmark());
		bookmarkManager.moveBookmarkUp(bookmark.getPath(), false);
		assertEquals("new position", currentPosition, positionOfBookmark(bookmarkManager, bookmark));
	}

	/**
	 * Tests that a bookmark category is moved up correctly by verifying the
	 * position after moving it.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testMoveBookmarkCategoryUp() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer category = findBookmarkCategory(bookmarkManager, Position.NOT_FIRST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(category.getPath())).getSubCategories().indexOf(category.getBookmark());
		bookmarkManager.moveBookmarkUp(category.getPath(), false);
		assertEquals("new position", currentPosition - 1, positionOfBookmarkCategory(bookmarkManager, category));
	}

	/**
	 * Tests that a bookmark category is not moved up when it is the first category
	 * in its parent category.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testDoNotMoveFirstBookmarkCategoryUp() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer category = findBookmarkCategory(bookmarkManager, Position.FIRST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(category.getPath())).getSubCategories().indexOf(category.getBookmark());
		bookmarkManager.moveBookmarkUp(category.getPath(), false);
		assertEquals("new position", currentPosition, positionOfBookmarkCategory(bookmarkManager, category));
	}

	/**
	 * Tests that a bookmark is moved down correctly by verifying the position
	 * after moving it.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testMoveBookmarkDown() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer bookmark = findBookmark(bookmarkManager, Position.NOT_LAST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(bookmark.getPath())).getItems().indexOf(bookmark.getBookmark());
		bookmarkManager.moveBookmarkDown(bookmark.getPath(), false);
		assertEquals("new position", currentPosition + 1, positionOfBookmark(bookmarkManager, bookmark));
	}

	/**
	 * Tests that a bookmark is not moved down when it is the last bookmark in its
	 * parent category.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testDoNotMoveLastBookmarkDown() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer bookmark = findBookmark(bookmarkManager, Position.LAST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(bookmark.getPath())).getItems().indexOf(bookmark.getBookmark());
		bookmarkManager.moveBookmarkDown(bookmark.getPath(), false);
		assertEquals("new position", currentPosition, positionOfBookmark(bookmarkManager, bookmark));
	}

	/**
	 * Tests that a bookmark category is moved down correctly by verifying the
	 * position after moving it.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testMoveBookmarkCategoryDown() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer category = findBookmarkCategory(bookmarkManager, Position.NOT_LAST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(category.getPath())).getSubCategories().indexOf(category.getBookmark());
		bookmarkManager.moveBookmarkDown(category.getPath(), false);
		assertEquals("new position", currentPosition + 1, positionOfBookmarkCategory(bookmarkManager, category));
	}

	/**
	 * Tests that a bookmark category is not moved down when it is the last
	 * category in its parent category.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testDoNotMoveLastBookmarkCategoryDown() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer category = findBookmarkCategory(bookmarkManager, Position.LAST);
		int currentPosition = bookmarkManager.getCategoryByPath(parentPath(category.getPath())).getSubCategories().indexOf(category.getBookmark());
		bookmarkManager.moveBookmarkDown(category.getPath(), false);
		assertEquals("new position", currentPosition, positionOfBookmarkCategory(bookmarkManager, category));
	}

	/**
	 * Moves a bookmark to another parent category and verifies that the move
	 * succeeded by checking the position of the bookmark in both the old and the
	 * new parent categories.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testMoveBookmarkToOtherParent() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer bookmark = findBookmark(bookmarkManager, Position.ANY);
		BookmarkContainer newParentCategory = findBookmarkCategory(bookmarkManager, Position.ANY, bookmarkManager.getCategoryByPath(parentPath(bookmark.getPath())));
		bookmarkManager.moveBookmark(bookmark.getPath(), newParentCategory.getPath());
		assertEquals("old position", -1, positionOfBookmark(bookmarkManager, bookmark));
		assertTrue("new position", positionOfBookmark(bookmarkManager, newParentCategory.getPath(), bookmark.getBookmark()) > -1);
	}

	/**
	 * Moves a bookmark category to another parent category and verifies that the
	 * move succeeded by checking the position of the bookmark category in both the
	 * old and the new parent categories.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testMoveBookmarkCategoryToOtherParent() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer category = findBookmarkCategory(bookmarkManager, Position.ANY);
		BookmarkContainer newParentCategory = findBookmarkCategory(bookmarkManager, Position.ANY, category.getBookmark(), bookmarkManager.getCategoryByPath(parentPath(category.getPath())));
		bookmarkManager.moveBookmark(category.getPath(), newParentCategory.getPath());
		assertEquals("old position", -1, positionOfBookmarkCategory(bookmarkManager, category));
		assertTrue("new position", positionOfBookmarkCategory(bookmarkManager, newParentCategory.getPath(), category.getBookmark()) > -1);
	}

	/**
	 * Tests renaming a bookmark and verifies it by searching for a bookmark with
	 * the new name in the same parent category.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testRenameBookmark() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer bookmark = findBookmark(bookmarkManager, Position.ANY);
		bookmarkManager.renameBookmark(bookmark.getPath(), "New Name");
		assertTrue("new name", positionOfBookmark(bookmarkManager, parentPath(bookmark.getPath()), "New Name") > -1);
	}

	/**
	 * Tests renaming a bookmark category and verifies it by searching for a
	 * bookmark category with the new name in the same parent category.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testRenameBookmarkCategory() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		BookmarkContainer category = findBookmarkCategory(bookmarkManager, Position.ANY);
		bookmarkManager.renameBookmark(category.getPath(), "New Category");
		assertTrue("new name", positionOfBookmarkCategory(bookmarkManager, parentPath(category.getPath()), "New Category") > -1);
	}

	/**
	 * Tests readd the default bookmark set by deleting all bookmarks and
	 * categories and readding the default bookmarks, checking the number of all
	 * bookmarks before deleting and after readding.
	 *
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	public void testReaddDefaultBookmarks() throws IOException {
		BookmarkManager bookmarkManager = createBookmarkManager();
		int oldSize = bookmarkManager.getBookmarks().getAllItems().size();
		for (BookmarkItem bookmarkItem : bookmarkManager.getBookmarks().getItems()) {
			bookmarkManager.removeBookmark("/" + bookmarkItem.getName());
		}
		for (BookmarkCategory bookmarkCategory : bookmarkManager.getBookmarks().getSubCategories()) {
			bookmarkManager.removeBookmark("/" + bookmarkCategory.getName() + "/");
		}
		assertEquals("bookmark manager empty", 0, bookmarkManager.getBookmarks().getAllItems().size());
		bookmarkManager.reAddDefaultBookmarks();
		assertEquals("size after readding default bookmarks", oldSize, bookmarkManager.getBookmarks().getAllItems().size());
	}

	//
	// PRIVATE METHODS
	//

	/**
	 * Creates a bookmark manager with the default bookmarks.
	 *
	 * @return A bookmark manager
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	private BookmarkManager createBookmarkManager() throws IOException {
		return createBookmarkManager(false);
	}

	/**
	 * Creates a bookmark manager with the default bookmarks.
	 *
	 * @param publicGateway
	 * 		{@code true} if the bookmark manager is created for a public gateway node,
	 * 		{@code false} otherwise
	 * @return A bookmark manager
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	private BookmarkManager createBookmarkManager(boolean publicGateway) throws IOException {
		File bookmarksFile = File.createTempFile("bookmarks-", ".dat");
		bookmarksFile.deleteOnExit();
		File backupBookmarksFile = File.createTempFile("bookmarks-", ".dat.bak");
		backupBookmarksFile.deleteOnExit();
		return createBookmarkManager(bookmarksFile, backupBookmarksFile, publicGateway);
	}

	/**
	 * Creates a bookmark manager that loads the bookmarks from and saves them to
	 * the given files.
	 *
	 * @param bookmarksFile
	 * 		The bookmarks file
	 * @param backupBookmarksFile
	 * 		The backup bookmarks file
	 * @param publicGateway
	 * 		{@code true} if the bookmark manager is created for a public gateway node,
	 * 		{@code false} otherwise
	 * @return A bookmark manager
	 * @throws IOException
	 * 		if an I/O error occurs
	 */
	private BookmarkManager createBookmarkManager(File bookmarksFile, File backupBookmarksFile, boolean publicGateway) {
		NodeClientCore nodeClientCore = mock(NodeClientCore.class);
		USKManager uskManager = mock(USKManager.class);
		return new BookmarkManager(nodeClientCore, uskManager, bookmarksFile, backupBookmarksFile, publicGateway);
	}

	/**
	 * Chooses a random bookmark other than the given bookmark from all the
	 * bookmarks of the given bookmark manager that satisfy the given position.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager to get a bookmark from
	 * @param position
	 * 		The position of the bookmark
	 * @param ignores
	 * 		The bookmarks to ignore
	 * @return A bookmark container, or {@code null} if no bookmark could be found
	 */

	private BookmarkContainer findBookmark(BookmarkManager bookmarkManager, Position position, Bookmark... ignores) {
		List<BookmarkContainer> items = findBookmark(bookmarkManager.getCategoryByPath("/"), "/", position);
		if (!items.isEmpty()) {
			List<BookmarkContainer> notIgnored = new ArrayList<BookmarkContainer>();
			List<Bookmark> ignored = Arrays.asList(ignores);
			for (BookmarkContainer bookmarkContainer : items) {
				if (!ignored.contains(bookmarkContainer.getBookmark())) {
					notIgnored.add(bookmarkContainer);
				}
			}
			if (notIgnored.isEmpty()) {
				return null;
			}
			return notIgnored.get((int) (Math.random() * notIgnored.size()));
		}
		return null;
	}

	/**
	 * Returns all bookmarks from the given category and all its subcategories
	 * satisfying the given position.
	 *
	 * @param category
	 * 		The category to get all bookmarks from
	 * @param path
	 * 		The path prefix for all returned bookmarks
	 * @param position
	 * 		The position requirement
	 * @return All located bookmarks
	 */
	private List<BookmarkContainer> findBookmark(BookmarkCategory category, String path, Position position) {
		/* first, scan items of given category. */
		List<BookmarkContainer> possibleChoices = new ArrayList<BookmarkContainer>();
		for (int index = 0, size = category.getItems().size(); index < size; ++index) {
			Bookmark bookmark = category.getItems().get(index);
			if (position == Position.ANY) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName(), bookmark));
			} else if ((position == Position.FIRST) && (index == 0)) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName(), bookmark));
			} else if ((position == Position.NOT_FIRST) && (index > 0)) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName(), bookmark));
			} else if ((position == Position.LAST) && (index == (size - 1))) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName(), bookmark));
			} else if ((position == Position.NOT_LAST) && (index < (size - 1))) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName(), bookmark));
			}
		}
		/* now recurse into sub categories. */
		for (BookmarkCategory subCategory : category.getSubCategories()) {
			possibleChoices.addAll(findBookmark(subCategory, path + subCategory.getName() + "/", position));
		}
		return possibleChoices;
	}

	/**
	 * Chooses a random bookmark category other than the given bookmark category
	 * from all the bookmark categories of the given bookmark manager that satisfy
	 * the given position.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager to get a bookmark category from
	 * @param position
	 * 		The position of the bookmark category
	 * @param ignores
	 * 		The bookmark categories to ignore
	 * @return A bookmark container, or {@code null} if no bookmark category could
	 *         be found
	 */
	private BookmarkContainer findBookmarkCategory(BookmarkManager bookmarkManager, Position position, Bookmark... ignores) {
		List<BookmarkContainer> categories = findBookmarkCategory(bookmarkManager.getCategoryByPath("/"), "/", position);
		if (!categories.isEmpty()) {
			List<BookmarkContainer> notIgnored = new ArrayList<BookmarkContainer>();
			List<Bookmark> ignored = Arrays.asList(ignores);
			for (BookmarkContainer bookmarkContainer : categories) {
				if (!ignored.contains(bookmarkContainer.getBookmark())) {
					notIgnored.add(bookmarkContainer);
				}
			}
			if (notIgnored.isEmpty()) {
				return null;
			}
			return notIgnored.get((int) (Math.random() * notIgnored.size()));
		}
		return null;
	}

	/**
	 * Returns all bookmarks categories from the given category and all its
	 * subcategories satisfying the given position.
	 *
	 * @param category
	 * 		The category to get all bookmark categories from
	 * @param path
	 * 		The path prefix for all returned bookmark categories
	 * @param position
	 * 		The position requirement
	 * @return All located bookmark categories
	 */
	private List<BookmarkContainer> findBookmarkCategory(BookmarkCategory category, String path, Position position) {
		/* first, scan items of given category. */
		List<BookmarkContainer> possibleChoices = new ArrayList<BookmarkContainer>();
		for (int index = 0, size = category.getSubCategories().size(); index < size; ++index) {
			Bookmark bookmark = category.getSubCategories().get(index);
			if (position == Position.ANY) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName() + "/", bookmark));
			} else if ((position == Position.FIRST) && (index == 0)) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName() + "/", bookmark));
			} else if ((position == Position.NOT_FIRST) && (index > 0)) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName() + "/", bookmark));
			} else if ((position == Position.LAST) && (index == (size - 1))) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName() + "/", bookmark));
			} else if ((position == Position.NOT_LAST) && (index < (size - 1))) {
				possibleChoices.add(new BookmarkContainer(path + bookmark.getName() + "/", bookmark));
			}
		}
		/* now recurse into sub categories. */
		for (BookmarkCategory subCategory : category.getSubCategories()) {
			possibleChoices.addAll(findBookmarkCategory(subCategory, path + subCategory.getName() + "/", position));
		}
		return possibleChoices;
	}

	/**
	 * Returns the position of the given bookmark in its parent category.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager
	 * @param bookmarkContainer
	 * 		The bookmark container
	 * @return The position of the bookmark, or {@code -1} if the bookmark could
	 *         not be found in its parent category
	 */
	private int positionOfBookmark(BookmarkManager bookmarkManager, BookmarkContainer bookmarkContainer) {
		return positionOfBookmark(bookmarkManager, parentPath(bookmarkContainer.getPath()), bookmarkContainer.getBookmark());
	}

	/**
	 * Returns the position of the given bookmark in the category specified by the
	 * given path.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager
	 * @param path
	 * 		The path of the parent category
	 * @param bookmark
	 * 		The bookmark whose position to check
	 * @return The position of the bookmark, or {@code -1} if the bookmark could
	 *         not be found
	 */
	private int positionOfBookmark(BookmarkManager bookmarkManager, String path, Bookmark bookmark) {
		return bookmarkManager.getCategoryByPath(path).getItems().indexOf(bookmark);
	}

	/**
	 * Returns the position of the bookmark with the given name in the category
	 * specified by the given path.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager
	 * @param path
	 * 		The path of the parent category
	 * @param name
	 * 		The name of the bookmark to find the position of
	 * @return The position of the bookmark, or {@code -1} if the bookmark could
	 *         not be found
	 */
	private int positionOfBookmark(BookmarkManager bookmarkManager, String path, String name) {
		int index = 0;
		for (Bookmark bookmark : bookmarkManager.getCategoryByPath(path).getItems()) {
			if (bookmark.getName().equals(name)) {
				return index;
			}
			index++;
		}
		return -1;
	}

	/**
	 * Returns the position of the given category in its parent category.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager
	 * @param bookmarkContainer
	 * 		The bookmark category container
	 * @return The position of the category, or {@code -1} if the bookmark could
	 *         not be found in its parent category
	 */
	private int positionOfBookmarkCategory(BookmarkManager bookmarkManager, BookmarkContainer bookmarkContainer) {
		return positionOfBookmarkCategory(bookmarkManager, parentPath(bookmarkContainer.getPath()), bookmarkContainer.getBookmark());
	}

	/**
	 * Returns the position of the given category in the category specified by the
	 * given path.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager
	 * @param path
	 * 		The path of the parent category
	 * @param category
	 * 		The category whose position to check
	 * @return The position of the category, or {@code -1} if the category could
	 *         not be found
	 */
	private int positionOfBookmarkCategory(BookmarkManager bookmarkManager, String path, Bookmark category) {
		return bookmarkManager.getCategoryByPath(path).getSubCategories().indexOf(category);
	}

	/**
	 * Returns the position of a category with the given name in the category
	 * specified by the given path.
	 *
	 * @param bookmarkManager
	 * 		The bookmark manager
	 * @param path
	 * 		The path of the parent category
	 * @param name
	 * 		The name of the category to find the position of
	 * @return The position of the category, or {@code -1} if the category could
	 *         not be found
	 */
	private int positionOfBookmarkCategory(BookmarkManager bookmarkManager, String path, String name) {
		int index = 0;
		for (Bookmark bookmark : bookmarkManager.getCategoryByPath(path).getSubCategories()) {
			if (bookmark.getName().equals(name)) {
				return index;
			}
			index++;
		}
		return -1;
	}

	/**
	 * Contains for a bookmark and its path.
	 *
	 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
	 *         (after refactoring)
	 */
	private static class BookmarkContainer {

		/** The path of the bookmark. */
		private final String path;

		/** The bookmark. */
		private final Bookmark bookmark;

		/**
		 * Creates a new bookmark container.
		 *
		 * @param path
		 * 		The path of the bookmark
		 * @param bookmark
		 * 		The bookmark
		 */
		private BookmarkContainer(String path, Bookmark bookmark) {
			this.path = path;
			this.bookmark = bookmark;
		}

		/**
		 * Returns the path of the bookmark.
		 *
		 * @return The path of the bookmark
		 */
		private String getPath() {
			return path;
		}

		/**
		 * Returns the bookmark.
		 *
		 * @return The bookmark
		 */
		private Bookmark getBookmark() {
			return bookmark;
		}

	}

}
