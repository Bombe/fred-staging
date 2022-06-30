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

package freenet.client.request;

/**
 * Must be implemented by any client object returned by SendableRequest.getClient().
 * Mostly this is for scheduling, but it does have one key purpose: to identify whether a
 * request is persistent or not.
 *
 * Use a {@link RequestClientBuilder} to conveniently build {@code RequestClient}s.
 *
 * @author toad
 */
public interface RequestClient {

	/**
	 * Is this request persistent? **Must not change!**
	 */
	boolean persistent();

	/**
	 * Send the request with the real time flag enabled? Real-time requests are given a
	 * higher priority in data transfers, but fewer of them are accepted. They are
	 * optimised for latency rather than throughput, and are expected to be bursty rather
	 * than continual. **Must not change!**
	 */
	boolean realTimeFlag();

}
