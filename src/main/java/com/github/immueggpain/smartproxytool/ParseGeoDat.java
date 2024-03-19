package com.github.immueggpain.smartproxytool;

import java.io.FileInputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.commons.net.util.SubnetUtils;

import com.github.immueggpain.smartproxy.Util;
import com.v2ray.core.app.router.routercommon.CIDR;
import com.v2ray.core.app.router.routercommon.GeoIP;
import com.v2ray.core.app.router.routercommon.GeoIPList;

public class ParseGeoDat {

	public static void main(String[] args) {
		try {
			new ParseGeoDat().run(args);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void run(String[] args) throws Exception {
		System.out.println("parse geoip.dat");
		GeoIPList geoIPList = GeoIPList.parseFrom(new FileInputStream("geoip.dat"));

		List<CIDR> cnCidrList = new ArrayList<>();
		for (GeoIP geoIP : geoIPList.getEntryList()) {
			// System.out.println(String.format("%s - %s ", geoIP.getCountryCode(), geoIP.getCidrCount()));
			if (geoIP.getCountryCode().equals("CN") || geoIP.getCountryCode().equals("PRIVATE"))
				cnCidrList.addAll(geoIP.getCidrList());
		}

		TreeMap<Long, Long> ordered = new TreeMap<>();
		for (CIDR cidr : cnCidrList) {
			InetAddress addr = InetAddress.getByAddress(cidr.getIp().toByteArray());
			if (addr instanceof Inet4Address) {
				// no support for ipv6 yet
			} else {
				continue;
			}
			String cidrNotation = String.format("%s/%d", addr.getHostAddress(), cidr.getPrefix());
			SubnetUtils subnet = new SubnetUtils(cidrNotation);
			subnet.setInclusiveHostCount(true);
			String low = subnet.getInfo().getLowAddress();
			String high = subnet.getInfo().getHighAddress();

			long lipLow = Util.ip2long(low);
			long lipHigh = Util.ip2long(high);

			ordered.put(lipLow, lipHigh);
		}

		ArrayList<String> outputLines = new ArrayList<>();
		long lastHigh = -1;
		for (Entry<Long, Long> entry : ordered.entrySet()) {
			long lipLow = entry.getKey();
			long lipHigh = entry.getValue();

			lastHigh++;
			if (lipLow > lastHigh)
				outputLines.add(String.format("%s %s proxy", Util.long2ip(lastHigh), Util.long2ip(lipLow - 1)));

			outputLines.add(String.format("%s %s direct", Util.long2ip(lipLow), Util.long2ip(lipHigh)));

			lastHigh = lipHigh;
		}

		Files.write(Paths.get("ip.rule"), outputLines);
	}

}
