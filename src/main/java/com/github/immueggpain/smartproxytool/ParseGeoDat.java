package com.github.immueggpain.smartproxytool;

import java.io.FileInputStream;
import java.net.InetAddress;
import java.util.List;

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

		List<CIDR> cnCidrList = null;
		for (GeoIP geoIP : geoIPList.getEntryList()) {
			System.out.println(String.format("%s - %s ", geoIP.getCountryCode(), geoIP.getCidrCount()));
			if (geoIP.getCountryCode().equals("CN"))
				cnCidrList = geoIP.getCidrList();
		}

		for (CIDR cidr : cnCidrList) {
			InetAddress addr = InetAddress.getByAddress(cidr.getIp().toByteArray());
			System.out.println(String.format("%s/%d %s", addr, cidr.getPrefix(), cidr.getIpAddr()));
		}
	}

}
