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

package freenet.client.async;

import freenet.client.request.RequestClient;
import freenet.support.io.ResumeFailedException;

/**
 * A client process. Something that initiates requests, and can cancel them. FCP, FProxy,
 * and the GlobalPersistentClient, implement this somewhere.
 */
public interface ClientBaseCallback {

	/**
	 * Called for a persistent request when the node is restarted. Must re-register with
	 * whatever infrastructure the request is using, e.g. PersistentRequestRoot,
	 * persistent temp buckets etc.
	 */
	void onResume(ClientContext context) throws ResumeFailedException;

	/**
	 * Get the RequestClient context object used to indicate which requests are related to
	 * each other for scheduling purposes.
	 */
	RequestClient getRequestClient();

}
