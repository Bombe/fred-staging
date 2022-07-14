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

package freenet.node.updater;

import java.util.HashMap;
import java.util.Map;

public enum UpdateFileType {

	MANIFEST("manifest"), MSI_X86_64("msi_x86_64");

	public final String label;

	private static final Map<String, UpdateFileType> BY_LABEL = new HashMap<>();

	static {
		for (UpdateFileType e : values()) {
			BY_LABEL.put(e.label, e);
		}
	}

	UpdateFileType(String label) {
		this.label = label;
	}

	public static UpdateFileType valueOfLabel(String label) {
		return BY_LABEL.get(label);
	}

}
