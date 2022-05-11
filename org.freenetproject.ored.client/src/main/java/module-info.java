/*
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

module org.freenetproject.ored.client {
    exports freenet.keys;
    exports freenet.bucket;
    exports freenet.checksum;
    exports freenet.client;
    exports freenet.client.async;
    exports freenet.client.events;
    exports freenet.client.filter;
    exports freenet.client.request;
    exports freenet.compress;
    exports freenet.lockablebuffer;
    exports freenet.http;

    requires org.freenetproject.ored.support;
    requires org.freenetproject.ored.crypt;
    requires org.freenetproject.ored.l10n;
    requires org.freenetproject.ored.config;
    requires org.bouncycastle.provider;
    requires org.apache.commons.compress;
    requires org.freenetproject.ext;
    requires org.tanukisoftware.wrapper;
    requires java.naming;
}