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

package freenet.cli.mixin;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import net.harawata.appdirs.AppDirs;
import net.harawata.appdirs.AppDirsFactory;
import picocli.CommandLine;

public class IniPathOption {

	public Path iniPath;

	@CommandLine.Spec
	CommandLine.Model.CommandSpec spec;

	@CommandLine.Option(names = "--ini-path", required = true, paramLabel = "PATH",
			description = "Path to freenet.ini. If not specified, I'll look for it in default user data directory.")
	void setIniPath(Path path) {
		if (path == null) {
			AppDirs appDirs = AppDirsFactory.getInstance();
			File userDataDir = new File(appDirs.getUserDataDir("ored", "", "Oldenet"));
			path = Paths.get(userDataDir.getAbsolutePath(), "freenet.ini");
		}

		this.iniPath = path;
	}

}
