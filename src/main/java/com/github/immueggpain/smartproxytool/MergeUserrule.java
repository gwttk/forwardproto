package com.github.immueggpain.smartproxytool;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;

import com.github.immueggpain.common.sc;
import com.github.immueggpain.common.scp;
import com.github.immueggpain.common.scp.ProcessResult;

/**
 * process user.rule. find rules like x.m.n & y.m.n, merge them into .m.n
 */
class MergeUserrule {

	private static final Pattern ping_regex_win = Pattern.compile("time([=<])([0-9]+)ms");

	public static class IpRange {
		public final long begin;
		public final long end;
		public final String target;

		public IpRange(long begin, long end, String target) {
			this.begin = begin;
			this.end = end;
			this.target = target;
		}
	}

	public static void main(String[] args) {
		try {
			new MergeUserrule().run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void run() throws Exception {
		load_domain_nn_table();
	}

	public static float ping_win(InetAddress ip) throws IOException {
		ProcessResult r = scp.collectResult(Runtime.getRuntime().exec("ping -n 1 " + ip.getHostAddress()));
		Matcher m = ping_regex_win.matcher(r.stdout);
		if (m.find()) {
			if (m.group(1).equals("<"))
				return Float.parseFloat(m.group(2)) - 0.5F;
			else
				return Float.parseFloat(m.group(2));
		} else
			return -1;
	}

	@SuppressWarnings("unused")
	private String queryIpRules(InetAddress addr) {
		long ip = ip2long(addr);
		IpRange ipRange = ip_to_nn.floorEntry(ip).getValue();
		if (ip > ipRange.end) {
			return null;
		} else {
			return ipRange.target;
		}
	}

	private static long ip2long(InetAddress ip) {
		byte[] parts = ip.getAddress();
		long ipLong = 0;
		for (int i = 0; i < 4; i++)
			ipLong += (parts[i] & 0xff) << (24 - (8 * i));
		return ipLong;
	}

	private static long ip2long(String ip) {
		String[] parts = ip.split("\\.");
		long ipLong = 0;
		for (int i = 0; i < 4; i++)
			ipLong += Integer.parseInt(parts[i]) << (24 - (8 * i));
		return ipLong;
	}

	public class DomainInfo {
		public String domain;
		public int count_proxy;
		public int count_direct;
	}

	private static final Pattern domain_regex = Pattern.compile("[a-z0-9-_]*(\\.[a-z0-9-_]+)*");
	private static final Pattern ip_regex = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
	private Map<String, DomainInfo> domain_to_nn;
	private NavigableMap<Long, IpRange> ip_to_nn;

	private void load_domain_nn_table() throws Exception {
		domain_to_nn = new HashMap<>();
		ip_to_nn = new TreeMap<>();
		Path path = Paths.get("user.rule");
		try (BOMInputStream is = new BOMInputStream(new FileInputStream(path.toFile()))) {
			for (String line : IOUtils.readLines(is, sc.utf8)) {
				line = line.trim();
				if (line.isEmpty())
					continue;
				if (line.startsWith("#"))
					continue;
				String[] segments = line.split(" ");
				if (ip_regex.matcher(segments[0]).matches()) {
					// ip
					if (segments.length != 3)
						throw new Exception("nn_table bad line " + line);
					if (!ip_regex.matcher(segments[1]).matches())
						throw new Exception("nn_table bad line " + line);
					String target;
					if (segments[2].equals("direct"))
						target = "direct";
					else if (segments[2].equals("reject"))
						target = "reject";
					else if (segments[2].equals("proxy"))
						target = "proxy";
					else
						throw new Exception("nn_table bad line " + line);
					long begin = ip2long(segments[0]);
					long end = ip2long(segments[1]);
					ip_to_nn.put(begin, new IpRange(begin, end, target));
					continue;
				}
				// domain
				if (segments.length != 2)
					throw new Exception("nn_table bad line: " + line);
				if (!domain_regex.matcher(segments[0]).matches())
					throw new Exception("nn_table bad line: " + line);
				String target;
				if (segments[1].equals("direct"))
					target = "direct";
				else if (segments[1].equals("reject"))
					target = "reject";
				else if (segments[1].equals("proxy"))
					target = "proxy";
				else
					throw new Exception("nn_table bad line " + line);
				String fulldn = segments[0];

				String intermediate;
				if (!fulldn.startsWith(".")) {
					DomainInfo domainInfo = domain_to_nn.get(fulldn);
					if (domainInfo == null) {
						domainInfo = new DomainInfo();
						domainInfo.domain = fulldn;
						domain_to_nn.put(fulldn, domainInfo);
					}
					if (target.equals("proxy"))
						domainInfo.count_proxy++;
					else if (target.equals("direct"))
						domainInfo.count_direct++;

					intermediate = "." + fulldn;
				} else
					intermediate = fulldn;

				while (true) {
					DomainInfo domainInfo = domain_to_nn.get(intermediate);
					if (domainInfo == null) {
						domainInfo = new DomainInfo();
						domainInfo.domain = intermediate;
						domain_to_nn.put(intermediate, domainInfo);
					}
					if (target.equals("proxy"))
						domainInfo.count_proxy++;
					else if (target.equals("direct"))
						domainInfo.count_direct++;

					int indexOf = intermediate.indexOf('.', 1);
					if (indexOf == -1)
						break;
					intermediate = intermediate.substring(indexOf);
				}
			}
		}

		for (Entry<String, DomainInfo> entry : domain_to_nn.entrySet()) {
			String dn = entry.getKey();
			DomainInfo info = entry.getValue();
			if (info.count_direct + info.count_proxy > 1)
				System.out.println(dn + " d" + info.count_direct + " p" + info.count_proxy);
		}
	}

}
