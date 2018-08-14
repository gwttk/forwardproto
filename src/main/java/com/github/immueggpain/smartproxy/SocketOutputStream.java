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
