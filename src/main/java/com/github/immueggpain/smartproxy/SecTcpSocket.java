package com.github.immueggpain.smartproxy;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.apache.commons.io.IOUtils;

public class SecTcpSocket implements Closeable {

	private Socket s;
	public InputStream is;
	public OutputStream os;
	private boolean closed = false;

	public SecTcpSocket(Socket raw) throws IOException {
		this.s = raw;
		if (s.isConnected() && !s.isClosed()) {
			this.is = new SocketInputStream(s);
			this.os = new SocketOutputStream(s);
		}
	}

	public Socket getRaw() {
		return s;
	}

	@SuppressWarnings("deprecation")
	@Override
	public void close() {
		if (closed)
			return;
		IOUtils.closeQuietly(is, os, s);
		closed = true;
	}
}
