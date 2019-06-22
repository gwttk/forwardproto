package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.apache.http.config.MessageConstraints;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.entity.StrictContentLengthStrategy;

public class Http2socks {

	private static final int bufferSize = 0;
	private static final int fragmentSizeHint = 0;

	public Http2socks() {
	}

	public void handleConnection(InputStream is, OutputStream os, Socket socket) {
		DefaultBHttpClientConnection connToDest = new DefaultBHttpClientConnection(bufferSize, fragmentSizeHint, null,
				null, MessageConstraints.DEFAULT, StrictContentLengthStrategy.INSTANCE,
				StrictContentLengthStrategy.INSTANCE, null, null);
		DefaultBHttpServerConnection connFromApp = new DefaultBHttpServerConnection(bufferSize, fragmentSizeHint, null,
				null, MessageConstraints.DEFAULT, StrictContentLengthStrategy.INSTANCE,
				StrictContentLengthStrategy.INSTANCE, null, null) {
			@Override
			protected InputStream getSocketInputStream(Socket socket) throws IOException {
				return is;
			}

			@Override
			protected OutputStream getSocketOutputStream(Socket socket) throws IOException {
				return os;
			}
		};
		try {
			connFromApp.bind(socket);
		} catch (IOException e) {
			throw new RuntimeException("this should be impossible", e);
		}
	}

}
