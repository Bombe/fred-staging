package freenet.test;

import freenet.support.SimpleFieldSet;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

public class SimpleFieldSetMatcher extends TypeSafeDiagnosingMatcher<SimpleFieldSet> {

	public static Matcher<SimpleFieldSet> matches(SimpleFieldSet expectedSimpleFieldSet) {
		return new SimpleFieldSetMatcher(expectedSimpleFieldSet);
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

	private SimpleFieldSetMatcher(SimpleFieldSet expectedSimpleFieldSet) {
		this.expectedSimpleFieldSet = expectedSimpleFieldSet;
	}

	private final SimpleFieldSet expectedSimpleFieldSet;

}
