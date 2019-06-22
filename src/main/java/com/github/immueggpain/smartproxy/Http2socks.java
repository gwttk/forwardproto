package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.config.MessageConstraints;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.entity.StrictContentLengthStrategy;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpProcessorBuilder;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.HttpRequestHandlerMapper;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.apache.http.protocol.UriHttpRequestHandlerMapper;
import org.apache.http.util.EntityUtils;

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
			protected InputStream getSocketInputStream(Socket socket) {
				return is;
			}

			@Override
			protected OutputStream getSocketOutputStream(Socket socket) {
				return os;
			}
		};

		try {
			connFromApp.bind(socket);
		} catch (IOException e) {
			throw new RuntimeException("this should be impossible", e);
		}

		HttpRequest requestFromApp = connFromApp.receiveRequestHeader();
		if (requestFromApp instanceof HttpEntityEnclosingRequest) {
			connFromApp.receiveRequestEntity((HttpEntityEnclosingRequest) requestFromApp);
			HttpEntity entity = ((HttpEntityEnclosingRequest) requestFromApp).getEntity();
			if (entity != null) {
				// Do something useful with the entity and, when done, ensure all
				// content has been consumed, so that the underlying connection
				// could be re-used
				EntityUtils.consume(entity);
			}
		}
		HttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_1, 200, "OK");
		response.setEntity(new StringEntity("Got it"));
		connFromApp.sendResponseHeader(response);
		connFromApp.sendResponseEntity(response);

		HttpProcessor httpproc = HttpProcessorBuilder.create().add(new ResponseDate())
				.add(new ResponseServer("MyServer-HTTP/1.1")).add(new ResponseContent()).add(new ResponseConnControl())
				.build();

		HttpRequestHandler myHandler = new HttpRequestHandler() {

			@Override
			public void handle(HttpRequest request, HttpResponse response, HttpContext context)
					throws HttpException, IOException {
				// TODO Auto-generated method stub

			}
		};

		HttpRequestHandlerMapper singleHandlerMapper = new HttpRequestHandlerMapper() {
			@Override
			public HttpRequestHandler lookup(HttpRequest request) {
				return myHandler;
			}
		};

		HttpContext context = HttpCoreContext.create();

		HttpService service = new HttpService(httpproc, DefaultConnectionReuseStrategy.INSTANCE,
				DefaultHttpResponseFactory.INSTANCE, singleHandlerMapper, null);
		service.handleRequest(connFromApp, context);
	}

}
