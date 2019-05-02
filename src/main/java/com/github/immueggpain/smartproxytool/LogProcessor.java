package com.github.immueggpain.smartproxytool;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.List;
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
 * process the log to get all default rules. ping them to check if DIRECT is
 * better than PROXY
 */
class LogProcessor {

	private static final Pattern ip_regex = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
	private static final Pattern ping_regex_win = Pattern.compile("time([=<])([0-9]+)ms");
	private static final Pattern default_line = Pattern
			.compile(".+ (?:socks5 |connect|http   ): PROXY  <- default <- (.+)");

	private NavigableMap<Long, IpRange> ip_to_nn;

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

	// args: log file path
	public static void main(String[] args) {
		try {
			new LogProcessor().run(args[0]);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void run(String logFilePath) throws Exception {
		load_domain_nn_table();
		HashSet<String> rules = new HashSet<>();
		HashSet<String> recordedDomains = new HashSet<>();
		HashSet<String> unpingableDomains = new HashSet<>();
		List<String> lines = Files.readAllLines(Paths.get(logFilePath), StandardCharsets.UTF_8);
		for (String line : lines) {
			Matcher m = default_line.matcher(line);
			if (m.find()) {
				String domainName = m.group(1);

				// check if already encountered
				if (recordedDomains.contains(domainName))
					continue;
				recordedDomains.add(domainName);

				// nslookup
				InetAddress addr;
				try {
					addr = InetAddress.getByName(domainName);
				} catch (UnknownHostException e) {
					continue;
				}

				float latency = -1;
				String target = null;

				float latency1 = ping_win(addr);
				float latency2 = ping_win(addr);
				if (latency1 < 0 || latency2 < 0) {
					unpingableDomains.add(domainName);
					target = queryIpRules(addr);
					rules.add(domainName + " " + target);
				} else {
					latency = (latency1 + latency2) / 2;

					if (latency <= 80) {
						target = "direct";
					} else if (latency > 160) {
						target = "proxy";
					} else {
						target = queryIpRules(addr);
					}
					rules.add(domainName + " " + target);

				}

				System.out.println(domainName + " " + addr.getHostAddress() + " " + latency + "ms " + target);
			}
		}
		System.out.println("==========rules:");
		for (String rule : rules) {
			System.out.println(rule);
		}
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

	private void load_domain_nn_table() throws Exception {
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
						target = segments[2];
					else if (segments[2].equals("reject"))
						target = segments[2];
					else if (segments[2].equals("proxy"))
						target = segments[2];
					else
						throw new Exception("nn_table bad line " + line);
					long begin = ip2long(segments[0]);
					long end = ip2long(segments[1]);
					ip_to_nn.put(begin, new IpRange(begin, end, target));
					continue;
				}
			}
		}
	}

}
