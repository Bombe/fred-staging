package freenet.test;

import java.util.Objects;

import freenet.support.SimpleFieldSet;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import static java.util.Spliterator.DISTINCT;
import static java.util.Spliterators.spliteratorUnknownSize;
import static java.util.stream.StreamSupport.stream;

public class SimpleFieldSetMatchers {

	public static Matcher<SimpleFieldSet> matches(SimpleFieldSet expectedSimpleFieldSet) {
		return new Matches(expectedSimpleFieldSet);
	}

	public static Matcher<SimpleFieldSet> hasKey(String key) {
		return new HasKey(key);
	}

	public static Matcher<SimpleFieldSet> hasKeyValue(String key, String value) {
		return new HasKeyValue(key, value);
	}

	private static class Matches extends TypeSafeDiagnosingMatcher<SimpleFieldSet> {

		private Matches(SimpleFieldSet expectedSimpleFieldSet) {
			this.expectedSimpleFieldSet = expectedSimpleFieldSet;
		}

		@Override
		protected boolean matchesSafely(SimpleFieldSet actualSimpleFieldSet, Description mismatchDescription) {
			if (!actualSimpleFieldSet.directKeyValues().equals(expectedSimpleFieldSet.directKeyValues())) {
				mismatchDescription.appendText("direct key values are ").appendValue(actualSimpleFieldSet.directKeyValues());
				return false;
			}
			if (!actualSimpleFieldSet.directSubsets().equals(expectedSimpleFieldSet.directSubsets())) {
				mismatchDescription.appendText("direct subsets are ").appendValue(actualSimpleFieldSet.directSubsets());
				return false;
			}
			return true;
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("is simple field set ").appendValue(expectedSimpleFieldSet);
		}

		private final SimpleFieldSet expectedSimpleFieldSet;

	}

	private static class HasKey extends TypeSafeDiagnosingMatcher<SimpleFieldSet> {

		private HasKey(String key) {
			this.key = key;
		}

		@Override
		protected boolean matchesSafely(SimpleFieldSet simpleFieldSet, Description mismatchDescription) {
			if (stream(spliteratorUnknownSize(simpleFieldSet.keyIterator(), DISTINCT), false).noneMatch(key -> key.equals(this.key))) {
				mismatchDescription.appendText("no ").appendValue(key).appendText(" in ").appendValue(simpleFieldSet.toString());
				return false;
			}
			return true;
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("is simple field set with key ").appendValue(key);
		}

		private final String key;

	}

	private static class HasKeyValue extends TypeSafeDiagnosingMatcher<SimpleFieldSet> {

		private HasKeyValue(String key, String value) {
			this.key = key;
			this.value = value;
		}

		@Override
		protected boolean matchesSafely(SimpleFieldSet simpleFieldSet, Description mismatchDescription) {
			if (!Objects.equals(simpleFieldSet.get(key), value)) {
				mismatchDescription.appendText("value of ").appendValue(key).appendText(" is ").appendValue(simpleFieldSet.get(key));
				return false;
			}
			return true;
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("is simple field set with ").appendValueList("(", ", ", ")", key, value);
		}

		private final String key;
		private final String value;

	}

}
