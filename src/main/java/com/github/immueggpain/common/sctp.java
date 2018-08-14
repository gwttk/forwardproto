package com.github.immueggpain.common;

/** sctp = shortcut for type conversion */
public final class sctp {

	private static final char[] hexArrayLow = "0123456789abcdef".toCharArray();

	/** byte -> 0x1f */
	public static String byte_to_string(byte b) {
		char[] hexChars = new char[2];
		int unsignedByte = b & 0xFF;
		hexChars[0] = hexArrayLow[unsignedByte >>> 4];
		hexChars[1] = hexArrayLow[unsignedByte & 0x0F];
		return "0x" + new String(hexChars);
	}

	public static short bytes_to_short(byte[] b, int offset) {
		int value = 0;
		for (int i = offset; i < 2 + offset; i++)
			value = (value << 8) + (b[i] & 0xff);
		return (short) value;
	}

	public static int bytes_to_ushort(byte[] b, int offset) {
		int value = 0;
		for (int i = offset; i < 2 + offset; i++)
			value = (value << 8) + (b[i] & 0xff);
		return value;
	}

	public static int bytes_to_int(byte[] b, int offset) {
		int value = 0;
		for (int i = offset; i < 4 + offset; i++)
			value = (value << 8) + (b[i] & 0xff);
		return value;
	}

	public static long bytes_to_uint(byte[] b, int offset) {
		long value = 0;
		for (int i = offset; i < 4 + offset; i++)
			value = (value << 8) + (b[i] & 0xff);
		return value;
	}

	/** 8 bytes to signed long, big endian */
	public static long bytes_to_long(byte[] b, int offset) {
		long value = 0;
		for (int i = offset; i < 8 + offset; i++)
			value = (value << 8) + (b[i] & 0xff);
		return value;
	}

	/** signed short to 2 bytes, big endian */
	public static void short_to_bytes(short value, byte[] buf, int offset) {
		for (int i = 0; i < 2; i++)
			buf[offset + i] = (byte) (value >> ((1 - i) * 8));
	}

	/** signed int to 4 bytes, big endian */
	public static void int_to_bytes(int value, byte[] buf, int offset) {
		for (int i = 0; i < 4; i++)
			buf[offset + i] = (byte) (value >> ((3 - i) * 8));
	}

	/** signed long to 8 bytes, big endian */
	public static void long_to_bytes(long value, byte[] buf, int offset) {
		for (int i = 0; i < 8; i++)
			buf[offset + i] = (byte) (value >> ((7 - i) * 8));
	}

}
