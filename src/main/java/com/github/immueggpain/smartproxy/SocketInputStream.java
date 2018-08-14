package com.github.immueggpain.smartproxy;

import java.io.FilterInputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * Socket.getInputStream() will return a stream. but calling the stream's close
 * will close the socket. <br>
 * Socket.shutdownInput() will also close socket.<br>
 * because of this, I created SocketInputStream. calling
 * SocketInputStream.close() will do nothing.
 */
public class SocketInputStream extends FilterInputStream {

	protected Socket s;

	public SocketInputStream(Socket s) throws IOException {
		super(s.getInputStream());
		this.s = s;
	}

	/** do nothing, even no shutdown. because shutdownInput also close socket */
	@Override
	public void close() {
	}

}
