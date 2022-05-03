package freenet.clients.fcp;

public interface RequestCompletionCallback {

	/**
	 * Callback called when a request succeeds.
	 */
	public void notifySuccess(FCPClientRequest req);
	
	/**
	 * Callback called when a request fails
	 */
	public void notifyFailure(FCPClientRequest req);
	
	/**
	 * Callback when a request is removed
	 */
	public void onRemove(FCPClientRequest req);
	
}
