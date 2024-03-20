package com.github.immueggpain.smartproxytool;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import com.github.immueggpain.smartproxy.Launcher;
import com.v2ray.core.app.router.routercommon.Domain;
import com.v2ray.core.app.router.routercommon.GeoSite;
import com.v2ray.core.app.router.routercommon.GeoSiteList;

import picocli.CommandLine.Command;

@Command(description = "Process geoip.dat, then output to ip.rule file.", name = "siterule",
		mixinStandardHelpOptions = true, version = Launcher.VERSTR)
public class ParseGeoSite implements Callable<Void> {

	public static void main(String[] args) {
		try {
			new ParseGeoSite().run(args);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public Void call() throws Exception {
		run(null);
		return null;
	}

	private void run(String[] args) throws Exception {
		System.out.println("parse geosite.dat");
		GeoSiteList geoSiteList = GeoSiteList.parseFrom(new FileInputStream("geosite.dat"));

		ArrayList<String> outputLines = new ArrayList<>();
		for (GeoSite geoSite : geoSiteList.getEntryList()) {
			outputLines.add(String.format("%s - %s ", geoSite.getCountryCode(), geoSite.getDomainCount()));
			for (Domain domain : geoSite.getDomainList()) {
				String line = String.format("\t%s - %s - %s", domain.getAttributeCount(), domain.getType(),
						domain.getValue());
				outputLines.add(line);
			}
		}
		Files.write(Paths.get("a.txt"), outputLines);
	}

}
