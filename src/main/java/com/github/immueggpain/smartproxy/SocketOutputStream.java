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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.net.Socket;

import javax.net.ssl.SSLSocket;

/**
 * Socket.getOutputStream() will return a stream. but calling the stream's close
 * will close the socket. <br>
 * because of this, I created SocketOutputStream. calling
 * SocketOutputStream.close() will not close socket. However, it will call
 * flush() and Socket.shutdownOutput(). <br>
 * But if the socket is an SSLSocket instance, even shutdownOutput() is not
 * called because SSLSocket does not support it. You must understand that SSL
 * has its own flush mechanism and you should not directly interfere with it
 * unless you clearly know what you are doing.
 */
public class SocketOutputStream extends FilterOutputStream {

	protected Socket s;

	public SocketOutputStream(Socket s) throws IOException {
		super(s.getOutputStream());
		this.s = s;
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		// must override this method because FilterOutputStream's implementation is so
		// wrong!
		out.write(b, off, len);
	}

	/** only shutdown, no close */
	@Override
	public void close() throws IOException {
		if (s.isOutputShutdown())
			return;
		out.flush();
		if (!(s instanceof SSLSocket))
			s.shutdownOutput();
	}

}
