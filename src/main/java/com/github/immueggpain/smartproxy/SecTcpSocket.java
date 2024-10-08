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

	@Override
	public void close() {
		if (closed)
			return;
		IOUtils.closeQuietly(is, os, s);
		closed = true;
	}
}
