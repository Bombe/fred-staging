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
 * Fluent-style builder for {@link RequestClient} implementations. The default {@code
 * RequestClient} built by this builder is not persistent and not real-time.
 *
 * @author <a href="mailto:bombe@freenetproject.org">David ‘Bombe’ Roden</a>
 */
public class RequestClientBuilder {

	private boolean persistent;

	private boolean realTime;

	public RequestClientBuilder persistent() {
		this.persistent = true;
		return this;
	}

	public RequestClientBuilder persistent(boolean persistent) {
		this.persistent = persistent;
		return this;
	}

	public RequestClientBuilder realTime() {
		this.realTime = true;
		return this;
	}

	public RequestClientBuilder realTime(boolean realTime) {
		this.realTime = realTime;
		return this;
	}

	/**
	 * Builds a {@link RequestClient}. Once this method has been called the returned
	 * {@code
	 * RequestClient} is not connected to this builder anymore; the resulting
	 * {@code RequestClient} will never change. With this it’s possible to reuse this
	 * builder instances for creating more {@code RequestClient}s.
	 * @return A new {@code RequestClient} with the given settings
	 */
	public RequestClient build() {
		return new RequestClient() {
			private final boolean persistent = RequestClientBuilder.this.persistent;

			private final boolean realTime = RequestClientBuilder.this.realTime;

			@Override
			public boolean persistent() {
				return this.persistent;
			}

			@Override
			public boolean realTimeFlag() {
				return this.realTime;
			}
		};
	}

}
