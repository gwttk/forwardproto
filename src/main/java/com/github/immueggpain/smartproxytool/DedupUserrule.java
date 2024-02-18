package com.github.immueggpain.smartproxytool;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BOMInputStream;

import com.github.immueggpain.common.sc;
import com.github.immueggpain.smartproxy.Launcher;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * process log, ping test unknown domains, add new rules to user.rule
 */
@Command(description = "Process unknown domains in log file, then update user.rule with new rules.", name = "uprule",
		mixinStandardHelpOptions = true, version = Launcher.VERSTR)
public class DedupUserrule implements Callable<Void> {

	@Option(names = { "-u", "--userrule" }, required = true, description = "user.rule file path")
	String outputUserRuleFile;

	@Option(names = { "-l", "--log" }, required = true, description = "log file path")
	String logFile;

	private static class IpRange {
		@SuppressWarnings("unused")
		public final long begin;
		public final long end;
		public final String target;

		public IpRange(long begin, long end, String target) {
			this.begin = begin;
			this.end = end;
			this.target = target;
		}
	}

	public Void call() throws Exception {
		// step 1: find all default domains in logfile.
		// ping test them, or lookup ip table if ping failed.
		// output new rules based on ping tests.
		Set<String> newRules = new LogProcessor().run(logFile);

		// step 2: read old user.rule into list of lines
		// merge old list with new list
		List<String> oldRules;
		try (BOMInputStream is = new BOMInputStream(new FileInputStream(Paths.get("user.rule").toFile()))) {
			oldRules = IOUtils.readLines(is, sc.utf8);
		}
		int localRuleSize = 0;
		try (BOMInputStream is = new BOMInputStream(new FileInputStream(Paths.get("local.rule").toFile()))) {
			List<String> localRules = IOUtils.readLines(is, sc.utf8);
			localRuleSize = localRules.size();
			oldRules.addAll(localRules);
		} catch (FileNotFoundException ignore) {
		}
		// notice the oldRules contain comments & empty lines.
		// also I want to insert new rules after the '#auto rules' line.
		ArrayList<String> merged = new ArrayList<String>(oldRules.size() + newRules.size());
		int insertIndx = oldRules.indexOf("#auto rules") + 1;
		merged.addAll(oldRules.subList(0, insertIndx));
		merged.addAll(newRules);
		merged.addAll(oldRules.subList(insertIndx, oldRules.size()));

		// step 3: find duplicates such as aaa.bbb.cc & ddd.bbb.cc
		// merge them into .bbb.cc
		new DedupUserrule().run(merged, outputUserRuleFile, localRuleSize);
		return null;
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

	private static final Pattern domain_regex = Pattern.compile("[a-z0-9-_]*(\\.[a-z0-9-_]+)*");
	private static final Pattern domain_line_regex = Pattern.compile("[a-z0-9-_]*(\\.[a-z0-9-_]+)* [a-z]+");
	private static final Pattern ip_regex = Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+");
	private NavigableMap<Long, IpRange> ip_to_nn;

	// domains
	private HashMap<String, String> domains;

	private void run(List<String> inputUserRules, String outputFile, int localRuleSize) throws Exception {
		domains = new HashMap<>();
		ArrayList<String> outputLines = new ArrayList<>();

		ip_to_nn = new TreeMap<>();
		for (String line : inputUserRules) {

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

			// don't add dot
//			if (!fulldn.startsWith(".")) {
//				fulldn = "." + fulldn;
//				outputLines.set(outputLines.size() - 1, fulldn + " " + target);
//			}

			String oldtarget = domains.get(fulldn);
			if (oldtarget == null)
				domains.put(fulldn, target);
			else if (oldtarget.equals(target)) {
				// dup
				outputLines.remove(outputLines.size() - 1);
			} else {
				// conflict
				System.err.println("error: same domain, different targets! " + fulldn);
				// this is an important error: same domain, different targets
			}
		}

		// remove redundant children
		int conflictCount = 0;
		for (Iterator<String> iterator = outputLines.iterator(); iterator.hasNext();) {
			String line = iterator.next();
			if (!domain_line_regex.matcher(line).matches()) {
				// not domain line
			} else {
				// domain line
				String[] segments = line.split(" ");
				String domain = segments[0];
				String target = segments[1];

				String parent = domain;

				while (true) {
					int indexOf = parent.indexOf('.', 1);
					if (indexOf == -1)
						break;
					parent = parent.substring(indexOf);

					String parentTarget = domains.get(parent);

					if (parentTarget != null) {
						// there's a parent
						if (parentTarget.equals(target)) {
							// this one is redundant
							System.out.println("redunt");
							System.out.println(String.format("parent: %s %s", parent, parentTarget));
							System.out.println(String.format("child: %s %s", domain, target));
							iterator.remove();
							break;// only remove once
						} else {
							// conflict with parent
							if (!isException(domain, target)) {
								System.err.println(String.format("%d conflict: parent: %s %s child: %s %s",
										conflictCount + 1, parent, parentTarget, domain, target));
								conflictCount++;
							}
						}
					}
				}
			}
		}

		System.out.println("====merge children with same target to sld(second level domain)");
		for (int i = 0; i < outputLines.size(); i++) {
			String line = outputLines.get(i);
			if (!domain_line_regex.matcher(line).matches()) {
				// not domain line
			} else {
				// domain line
				String[] segments = line.split(" ");
				String domain = segments[0];
				String target = segments[1];

				String sld = getSLD(domain);

				// if domain is already sld, skip
				if (sld.equals(domain))
					continue;

				// if all other domain of same sld are same target, ascend me to sld
				boolean consistent = true;
				// if there's another sld with same target, delete me
				boolean deleteMe = false;
				for (String line2 : outputLines) {
					if (!domain_line_regex.matcher(line2).matches()) {
						// not domain line
					} else {
						// domain line
						String[] segments2 = line2.split(" ");
						String domain2 = segments2[0];
						String target2 = segments2[1];

						String sld2 = getSLD(domain2);
						if (!sld2.equals(sld))
							continue;
						if (sld2.equals(domain2))
							deleteMe = true;
						if (!target2.equals(target))
							consistent = false;
					}
				}

				// now what to do with me
				if (consistent) {
					if (deleteMe) {
						outputLines.remove(i);
						i--;
					} else
						outputLines.set(i, sld + " " + target);
				} else {
					// do nothing
				}
			}
		}

		// write output with utf8 BOM
		outputLines.set(0, "\ufeff" + outputLines.get(0));
		Files.write(Paths.get(outputFile), outputLines.subList(0, outputLines.size() - localRuleSize));
	}

	private static HashMap<String, String> excepRules = new HashMap<String, String>();

	static {
		excepRules.put(".bloomberg.cn", "proxy");
		excepRules.put(".sonkwo.hk", "direct");
		excepRules.put(".cms-origin-cn.battle.net", "direct");
		excepRules.put(".pw.gigazine.net", "direct");
		excepRules.put(".cn.news.blizzard.com", "direct");
		excepRules.put(".cache-cn.battle.net", "direct");
		excepRules.put(".cdn.q1mediahydraplatform.com", "proxy");
		excepRules.put(".daxa.cn", "proxy");
		excepRules.put(".kissbbao.cn", "proxy");
		excepRules.put(".cn.patch.battle.net", "direct");
		excepRules.put(".cache-cms-ext-cn.battle.net", "direct");
		excepRules.put(".qixianglu.cn", "proxy");
		excepRules.put(".sjum.cn", "proxy");
		excepRules.put(".syx86.cn", "proxy");
		excepRules.put(".sjum.cn", "proxy");
		excepRules.put(".pmt-origin-cn.battle.net", "direct");
		excepRules.put(".jd.hk", "direct");
		excepRules.put(".unagi-cn.amazon.com", "direct");
		excepRules.put(".fls-cn.amazon.com", "direct");
		excepRules.put(".ctrip.co.kr", "direct");
		excepRules.put(".taiwandao.tw", "direct");
		excepRules.put(".unagi-cn.amazon.com", "direct");
		excepRules.put(".render-api-cn.worldofwarcraft.com", "direct");
		excepRules.put(".forums.mihoyo.com", "proxy");
	}

	/** some domains are exceptions as they differ from parent domains. */
	private static boolean isException(String domain, String target) {
		String target_ = excepRules.get(domain);
		if (target.equals(target_))
			return true;
		else
			return false;
	}

	private static String getSLD(String fullDomain) {
		int firstDot = fullDomain.lastIndexOf('.', fullDomain.length() - 1);
		int secondDot = fullDomain.lastIndexOf('.', firstDot - 1);
		if (secondDot == -1)
			return fullDomain;
		return fullDomain.substring(secondDot);
	}

}
