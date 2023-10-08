package freenet.test;

import freenet.support.SimpleFieldSet;
import org.junit.Test;

import static freenet.test.SimpleFieldSetMatchers.hasKey;
import static freenet.test.SimpleFieldSetMatchers.hasKeyValue;
import static freenet.test.SimpleFieldSetMatchers.matches;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;

public class SimpleFieldSetMatcherTest {

	@Test
	public void matcherCanMatchTwoEmptySimpleFieldSets() {
		assertThat(new SimpleFieldSet(true), matches(new SimpleFieldSet(true)));
	}

	@Test
	public void matcherMatchesTwoSimpleFieldSetsWithDifferentShortLivedAttribute() {
		assertThat(new SimpleFieldSet(false), matches(new SimpleFieldSet(true)));
	}

	@Test
	public void matcherCanDetectMismatchBetweenTwoSimpleFieldSetsWithOneStringValue() {
		SimpleFieldSet expectedSimpleFieldSet = new SimpleFieldSet(true);
		expectedSimpleFieldSet.putSingle("test", "foo");
		SimpleFieldSet differentSimpleFieldSet = new SimpleFieldSet(true);
		differentSimpleFieldSet.putSingle("test", "bar");
		assertThat(differentSimpleFieldSet, not(matches(expectedSimpleFieldSet)));
	}

	@Test
	public void matcherCanMatchTwoSimpleFieldSetsWithOneStringValue() {
		SimpleFieldSet expectedSimpleFieldSet = new SimpleFieldSet(true);
		expectedSimpleFieldSet.putSingle("test", "foo");
		assertThat(new SimpleFieldSet(expectedSimpleFieldSet), matches(expectedSimpleFieldSet));
	}

	@Test
	public void matcherCanDetectDifferentKeysBeingPresent() {
		SimpleFieldSet expectedSimpleFieldSet = new SimpleFieldSet(true);
		expectedSimpleFieldSet.putSingle("foo", "test");
		SimpleFieldSet differentSimpleFieldSet = new SimpleFieldSet(true);
		differentSimpleFieldSet.putSingle("bar", "test");
		assertThat(differentSimpleFieldSet, not(matches(expectedSimpleFieldSet)));
	}

	@Test
	public void matcherCanDetectMismatchBetweenSubsets() {
		SimpleFieldSet expectedSimpleFieldSet = new SimpleFieldSet(true);
		expectedSimpleFieldSet.putSingle("test.foo", "bar");
		SimpleFieldSet differentSimpleFieldSet = new SimpleFieldSet(true);
		differentSimpleFieldSet.putSingle("bar", "test");
		assertThat(differentSimpleFieldSet, not(matches(expectedSimpleFieldSet)));
	}

	@Test
	public void matcherCanDetectMismatchInSubsets() {
		SimpleFieldSet expectedSimpleFieldSet = new SimpleFieldSet(true);
		expectedSimpleFieldSet.putSingle("test.foo", "bar");
		SimpleFieldSet differentSimpleFieldSet = new SimpleFieldSet(true);
		differentSimpleFieldSet.putSingle("test.foo", "test");
		assertThat(differentSimpleFieldSet, not(matches(expectedSimpleFieldSet)));
	}

	@Test
	public void matcherCanDetectMismatchInNestedSubsets() {
		SimpleFieldSet expectedSimpleFieldSet = new SimpleFieldSet(true);
		expectedSimpleFieldSet.putSingle("test.foo.bar", "yes");
		SimpleFieldSet differentSimpleFieldSet = new SimpleFieldSet(true);
		differentSimpleFieldSet.putSingle("test.foo.bar", "no");
		assertThat(differentSimpleFieldSet, not(matches(expectedSimpleFieldSet)));
	}

	@Test
	public void matcherCanDetectPresenceOfKeyInSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("test", "yes");
		assertThat(simpleFieldSet, hasKey("test"));
	}

	@Test
	public void matcherCanDetectPresenceOfKeyInSubsetsOfSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("test.foo", "yes");
		assertThat(simpleFieldSet, hasKey("test.foo"));
	}

	@Test
	public void matcherCanDetectNonPresenceOfKeyInSubsetsOfSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("test.foo", "yes");
		assertThat(simpleFieldSet, not(hasKey("bar")));
	}

	@Test
	public void matcherCanDetectValueMismatchOfKeyValuePairInSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("test", "yes");
		assertThat(simpleFieldSet, not(hasKeyValue("test", "foo")));
	}

	@Test
	public void matcherCanDetectAbsenceOfKeyValuePairInSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		assertThat(simpleFieldSet, not(hasKeyValue("test", "foo")));
	}

	@Test
	public void matcherCanDetectPresenceOfKeyValuePairInSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("test", "yes");
		assertThat(simpleFieldSet, hasKeyValue("test", "yes"));
	}

	@Test
	public void matcherCanDetectPresenceOfNestedKeyValuePairInSimpleFieldSet() {
		SimpleFieldSet simpleFieldSet = new SimpleFieldSet(true);
		simpleFieldSet.putSingle("test.foo", "yes");
		assertThat(simpleFieldSet, hasKeyValue("test.foo", "yes"));
	}

}
