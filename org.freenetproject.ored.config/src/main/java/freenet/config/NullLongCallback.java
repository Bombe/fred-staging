package freenet.config;

public class NullLongCallback extends LongCallback {

	@Override
	public Long get() {
		return 0L;
	}

	@Override
	public void set(Long val) throws InvalidConfigValueException {
		// Ignore
	}

}
