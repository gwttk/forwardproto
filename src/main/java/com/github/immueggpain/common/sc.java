/*******************************************************************************
 * MIT License
 *
 * Copyright (c) 2018 Immueggpain
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *******************************************************************************/
package com.github.immueggpain.common;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.Random;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/** sc = shortcut */
public final class sc {

	public static final Charset utf8 = StandardCharsets.UTF_8;

	public static void main(String[] args) {
		byte[] b = new byte[4];
		b[0] = 1;
		b[1] = -1;
		b[2] = 1;
		b[3] = 1;
		int[] h = b2ushort(b, 4);
		System.out.println(h[0] + "," + h[1]);
	}

	public static byte[] s2b(String s) {
		return s.getBytes(utf8);
	}

	public static String b2s(byte[] b) {
		return new String(b, utf8);
	}

	public static String b2s(byte[] b, int offset, int length) {
		return new String(b, offset, length, utf8);
	}

	/** big endian byte array to unsigned short array */
	public static int[] b2ushort(byte[] b, int len) {
		int hlen = len / 2;
		int[] h = new int[hlen];
		for (int i = 0; i < hlen; i++)
			h[i] = ((b[2 * i]) << 8) + (b[2 * i + 1] & 0xff);
		return h;
	}

	/** [a-zA-Z_0-9]+ */
	public static boolean isWord(String s) {
		return s.matches("\\w+");
	}

	/** better use SystemUtils.IS_OS_XXXXX */
	public static String getOS() {
		return System.getProperty("os.name");
	}

	/**
	 * {@link #execCommandR(String, boolean) execCommandR(command, true)}
	 */
	public static ExecCmdRet execCommandR(String command) throws IOException, InterruptedException {
		return execCommandR(command, true);
	}

	/**
	 * wait for process terminated and return 1&2&exitValue in strings.
	 * 
	 * @param print
	 *            if true, print command
	 */
	public static ExecCmdRet execCommandR(String command, boolean print) throws IOException, InterruptedException {
		if (print)
			System.out.println("exec: " + command);
		Process pro = Runtime.getRuntime().exec(command);
		pro.waitFor();
		ExecCmdRet r = new ExecCmdRet();
		r.stdout = IOUtils.toString(pro.getInputStream(), Charset.defaultCharset());
		r.stderr = IOUtils.toString(pro.getErrorStream(), Charset.defaultCharset());
		r.rcode = pro.exitValue();
		return r;
	}

	/** just exec, don't wait */
	public static Process execCommandAsync(String command) throws IOException, InterruptedException {
		System.out.println("exec: " + command);
		Process pro = Runtime.getRuntime().exec(command);
		return pro;
	}

	/** just exec, don't wait */
	public static Process execCommandAsync(String... command) throws IOException, InterruptedException {
		System.out.println("exec: " + command);
		Process pro = Runtime.getRuntime().exec(command);
		return pro;
	}

	public static class ExecCmdRet {
		public String stdout;
		public String stderr;
		public int rcode;
	}

	public static void printArray(Object a) {
		System.out.println(strArray(a));
	}

	public static void printArray(Object a, int length) {
		System.out.println(strArray(a, length));
	}

	public static String strArray(Object a) {
		if (a == null)
			return "null";
		String s = "[";
		int length = Array.getLength(a);
		for (int index = 0; index < length; index++) {
			Object object = Array.get(a, index);
			s += object;
			if (index < length - 1)
				s += ", ";
		}
		return s + "]";
	}

	public static String strArray(Object a, int length) {
		String s = "[";
		for (int index = 0; index < length; index++) {
			Object object = Array.get(a, index);
			s += object;
			if (index < length - 1)
				s += ", ";
		}
		return s + "]";
	}

	/**
	 * {@link #randomStr(int) randomStr(130)}. <br>
	 * 130 bits, base32, 26 chars <br>
	 * I choose 130 because bigger than 128.
	 */
	public static String randomStr() {
		return randomStr(130);
	}

	/**
	 * {@link #randomStr(int, Random) randomStr(bits, new SecureRandom())} <br>
	 * base32, which is 5 bit per char
	 */
	public static String randomStr(int bits) {
		return randomStr(bits, new SecureRandom());
	}

	/** base32, which is 5 bit per char */
	public static String randomStr(int bits, Random random) {
		return new BigInteger(bits, random).toString(32);
	}

	/** print object like json style. no inherited fields, no recursion */
	public static String toString(Object o) {
		StringBuilder sb = new StringBuilder();
		sb.append('{');
		Field[] fields = o.getClass().getDeclaredFields();
		for (int i = 0; i < fields.length; i++) {
			Field field = fields[i];
			field.setAccessible(true);
			sb.append(field.getName());
			sb.append(": ");
			try {
				sb.append(field.get(o));
			} catch (Exception e) {
				e.printStackTrace();
			}
			if (i < fields.length - 1)
				sb.append(", ");
		}
		sb.append('}');
		return sb.toString();
	}

	public static String percent(double v) {
		return String.format("%d%%", (int) (v * 100));
	}

	public static void redirect_sysout(String file, boolean append)
			throws UnsupportedEncodingException, FileNotFoundException {
		System.setOut(new PrintStream(new FileOutputStream(file, append), true, "utf-8"));
	}

	public static void redirect_syserr(String file, boolean append)
			throws UnsupportedEncodingException, FileNotFoundException {
		System.setErr(new PrintStream(new FileOutputStream(file, append), true, "utf-8"));
	}

	final protected static char[] hexArrayUp = "0123456789ABCDEF".toCharArray();
	final protected static char[] hexArrayLow = "0123456789abcdef".toCharArray();

	/** byte[] to hex string lower case */
	public static String b2hex(byte[] bytes) {
		return b2hex(bytes, 0, bytes.length);
	}

	/** byte[] to hex string lower case */
	public static String b2hex(byte[] bytes, int offset, int length) {
		char[] hexChars = new char[length * 2];
		for (int j = offset; j < length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArrayLow[v >>> 4];
			hexChars[j * 2 + 1] = hexArrayLow[v & 0x0F];
		}
		return new String(hexChars);
	}

	/**
	 * hex string lower case to byte[]
	 * 
	 * @throws DecoderException
	 */
	public static byte[] hex2b(String hex) throws DecoderException {
		return Hex.decodeHex(hex.toCharArray());
	}

	public static String getOSLanguage() {
		Locale locale = Locale.getDefault();
		String language = locale.getLanguage();
		return language;
	}

	/** find 1st capture */
	public static String match(String regex, String input) {
		Pattern p = Pattern.compile(regex);
		Matcher m = p.matcher(input);
		m.find();
		return m.group(1);
	}

	/** find 1st capture */
	public static List<String> capture(String regex, String input) {
		Pattern p = Pattern.compile(regex);
		Matcher m = p.matcher(input);
		m.find();
		ArrayList<String> li = new ArrayList<>();
		for (int i = 1; i <= m.groupCount(); i++) {
			li.add(m.group(i));
		}
		return li;
	}

	public static <T> Iterable<T> getIterable(Stream<T> stream) {
		return stream::iterator;
	}

	public static boolean equals(Object a, Object b) {
		if (a == null)
			return b == null;
		return a.equals(b);
	}

	/** if o==null, return ""; otherwise return o.toString(). */
	public static String stringOrEmpty(Object o) {
		if (o == null)
			return "";
		else
			return o.toString();
	}

	public static void print(Object o) {
		Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
		System.out.println(gson.toJson(o));
	}

}
