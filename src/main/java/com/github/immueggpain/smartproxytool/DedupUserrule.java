package com.github.immueggpain.smartproxytool;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
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
 * process user.rule. find dups
 */
class DedupUserrule {

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

	// args: new user.rule file path
	public static void main(String[] args) {
		try {
			new DedupUserrule().run(args);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void run(String[] args) throws Exception {
		run(args[0]);
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
	private NavigableMap<Long, IpRange> ip_to_nn;

	// domains
	private HashMap<String, String> domains;

	private void run(String outputFile) throws Exception {
		domains = new HashMap<>();
		ArrayList<String> outputLines = new ArrayList<>();

		ip_to_nn = new TreeMap<>();
		Path path = Paths.get("user.rule");
		try (BOMInputStream is = new BOMInputStream(new FileInputStream(path.toFile()))) {
			for (String line : IOUtils.readLines(is, sc.utf8)) {

				line = line.trim();

				// add line first, then delete it maybe
				outputLines.add(line);

				if (line.isEmpty())
					continue;
				if (line.startsWith("#"))
					continue;
				String[] segments = line.split(" ");

				// handle a line of ip rule
				if (ip_regex.matcher(segments[0]).matches()) {
					// ip
					if (segments.length != 3)
						throw new Exception("user.rule bad line " + line);
					if (!ip_regex.matcher(segments[1]).matches())
						throw new Exception("user.rule bad line " + line);
					String target;
					if (segments[2].equals("direct"))
						target = "direct";
					else if (segments[2].equals("reject"))
						target = "reject";
					else if (segments[2].equals("proxy"))
						target = "proxy";
					else
						throw new Exception("user.rule bad line " + line);
					long begin = ip2long(segments[0]);
					long end = ip2long(segments[1]);
					ip_to_nn.put(begin, new IpRange(begin, end, target));
					continue;
				}

				// a line of domain rule
				if (segments.length != 2)
					throw new Exception("user.rule bad line: " + line);
				if (!domain_regex.matcher(segments[0]).matches())
					throw new Exception("user.rule bad line: " + line);

				// parse target(proxy/direct)
				String target;
				if (segments[1].equals("direct"))
					target = "direct";
				else if (segments[1].equals("reject"))
					target = "reject";
				else if (segments[1].equals("proxy"))
					target = "proxy";
				else
					throw new Exception("user.rule bad line " + line);

				//
				String fulldn = segments[0];
				String oldtarget = domains.get(fulldn);
				if (oldtarget == null)
					domains.put(fulldn, target);
				else if (oldtarget.equals(target)) {
					// dup
					outputLines.remove(outputLines.size() - 1);
				} else {
					// conflict
					System.err.println("conflict! " + fulldn);
				}
			}
		} // end of open file

		// write output
		Files.write(Paths.get(outputFile), outputLines);
	}

}
