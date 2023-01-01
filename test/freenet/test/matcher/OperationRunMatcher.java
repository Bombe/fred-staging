package freenet.test.matcher;

import freenet.node.stats.CompressionStats.OperationRun;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeDiagnosingMatcher;

import static org.hamcrest.Matchers.any;

/**
 * Hamcrest matcher for an {@link OperationRun}.
 */
public class OperationRunMatcher extends TypeSafeDiagnosingMatcher<OperationRun> {

	/**
	 * Returns a matcher that will match an {@link OperationRun} by algorithm, size before the operation, and size after the operation.
	 * In other words, this matcher ignores the duration of a compression operation run.
	 *
	 * @param algorithm The algorithm to match
	 * @param sizeBeforeOperation The size before the operation to match
	 * @param sizeAfterOperation The size after the operation to match
	 * @return A matcher that matches the given values
	 */
	public static Matcher<OperationRun> matchesOperationRun(String algorithm, long sizeBeforeOperation, long sizeAfterOperation) {
		return matchesOperationRun(algorithm, any(Long.class), sizeBeforeOperation, sizeAfterOperation);
	}

	/**
	 * Returns a matcher that will match an {@link OperationRun} by algorithm, duration, size before the operation, and size after the operation.
	 *
	 * @param algorithm The algorithm to match
	 * @param durationMatcher Matcher for the duration
	 * @param sizeBeforeOperation The size before the operation to match
	 * @param sizeAfterOperation The size after the operation to match
	 * @return A matcher that matches the given values
	 */
	public static Matcher<OperationRun> matchesOperationRun(String algorithm, Matcher<Long> durationMatcher, long sizeBeforeOperation, long sizeAfterOperation) {
		return new OperationRunMatcher(algorithm, durationMatcher, sizeBeforeOperation, sizeAfterOperation);
	}

	@Override
	protected boolean matchesSafely(OperationRun run, Description mismatchDescription) {
		if (!run.algorithm.equals(algorithm)) {
			mismatchDescription.appendText("algorithm is ").appendValue(run.algorithm);
			return false;
		}
		if (!durationMatcher.matches(run.duration)) {
			mismatchDescription.appendText("duration is ").appendValue(run.duration);
			return false;
		}
		if (run.sizeBeforeOperation != sizeBeforeOperation) {
			mismatchDescription.appendText("sizeBeforeOperation is ").appendValue(run.sizeBeforeOperation);
			return false;
		}
		if (run.sizeAfterOperation != sizeAfterOperation) {
			mismatchDescription.appendText("sizeAfterOperation is ").appendValue(run.sizeAfterOperation);
			return false;
		}
		return true;
	}

	@Override
	public void describeTo(Description description) {
		description.appendText("run with algorithm ").appendValue(algorithm)
				.appendText(", duration ").appendDescriptionOf(durationMatcher)
				.appendText(", sizeBeforeCompression ").appendValue(sizeBeforeOperation)
				.appendText(", sizeAfterCompression ").appendValue(sizeAfterOperation);
	}

	private OperationRunMatcher(String algorithm, Matcher<Long> durationMatcher, long sizeBeforeOperation, long sizeAfterOperation) {
		this.algorithm = algorithm;
		this.durationMatcher = durationMatcher;
		this.sizeBeforeOperation = sizeBeforeOperation;
		this.sizeAfterOperation = sizeAfterOperation;
	}

	private final String algorithm;
	private final Matcher<Long> durationMatcher;
	private final long sizeBeforeOperation;
	private final long sizeAfterOperation;

}
