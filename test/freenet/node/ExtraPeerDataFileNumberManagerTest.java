package freenet.node;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;

public class ExtraPeerDataFileNumberManagerTest {

	@Test
	public void newManagerHasNoFileNumbers() {
		assertThat(manager.getFileNumbers(), empty());
	}

	@Test
	public void addingAFileNumberRetainsTheFileNumber() {
		manager.addFileNumber(123);
		assertThat(manager.getFileNumbers(), containsInAnyOrder(123));
	}

	@Test
	public void addingFileNumbersRetainsAddedUniqueFileNumbers() {
		manager.addFileNumber(123);
		manager.addFileNumber(234);
		manager.addFileNumber(345);
		manager.addFileNumber(234);
		assertThat(manager.getFileNumbers(), containsInAnyOrder(123, 234, 345));
	}

	@Test
	public void addedFileNumbersAreSortedWhenReturned() {
		manager.addFileNumber(234);
		manager.addFileNumber(123);
		manager.addFileNumber(345);
		assertThat(manager.getFileNumbers(), contains(123, 234, 345));
	}

	@Test
	public void allocatingANewFileNumberReturnsAndAllocatesFileNumber0() {
		assertThat(manager.allocateNextFileNumber(), equalTo(0));
		assertThat(manager.getFileNumbers(), contains(0));
	}

	@Test
	public void allocatingANewFileNumberWhenThreeFileNumbersHaveBeenAddedReturns3() {
		manager.addFileNumber(0);
		manager.addFileNumber(1);
		manager.addFileNumber(2);
		assertThat(manager.allocateNextFileNumber(), equalTo(3));
		assertThat(manager.getFileNumbers(), contains(0, 1, 2, 3));
	}

	@Test
	public void allocatingANewFileNumberWhenFileNumbersWithAHoleInThemHaveBeenAddedReturnsFileNumberInHole() {
		manager.addFileNumber(0);
		manager.addFileNumber(1);
		manager.addFileNumber(4);
		assertThat(manager.allocateNextFileNumber(), equalTo(2));
		assertThat(manager.getFileNumbers(), contains(0, 1, 2, 4));
	}

	@Test
	public void removingAFileNumberRemovesTheFileNumberLeavingAHole() {
		manager.addFileNumber(0);
		manager.addFileNumber(1);
		manager.addFileNumber(2);
		manager.removeFileNumber(1);
		assertThat(manager.getFileNumbers(), contains(0, 2));
	}

	private final ExtraPeerDataFileNumberManager manager = new ExtraPeerDataFileNumberManager();

}
