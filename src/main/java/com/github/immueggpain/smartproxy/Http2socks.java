package com.github.immueggpain.smartproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.Future;

import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.HttpClientConnection;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.config.MessageConstraints;
import org.apache.http.impl.DefaultBHttpClientConnection;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.entity.StrictContentLengthStrategy;
import org.apache.http.impl.pool.BasicConnFactory;
import org.apache.http.impl.pool.BasicConnPool;
import org.apache.http.impl.pool.BasicPoolEntry;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpProcessorBuilder;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.HttpRequestHandlerMapper;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.apache.http.util.EntityUtils;

public class Http2socks {

	private static final int bufferSize = 0;
	private static final int fragmentSizeHint = 0;

	private final HttpRequestHandlerMapper singleHandlerMapper = new HttpRequestHandlerMapper() {
		@Override
		public HttpRequestHandler lookup(HttpRequest request) {
			return Http2socks.this::handle;
		}
	};

	public Http2socks() {
	}

	public void handleConnection(InputStream is, OutputStream os, Socket socket) {
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

		HttpProcessor httpproc = HttpProcessorBuilder.create().add(new ResponseDate())
				.add(new ResponseServer("MyServer-HTTP/1.1")).add(new ResponseContent()).add(new ResponseConnControl())
				.build();

		HttpContext context = HttpCoreContext.create();

		HttpService service = new HttpService(httpproc, DefaultConnectionReuseStrategy.INSTANCE,
				DefaultHttpResponseFactory.INSTANCE, singleHandlerMapper, null);

		do {
			try {
				service.handleRequest(connFromApp, context);
			} catch (IOException | HttpException e) {
				System.err.println("error connection from app broken, shutdown");
				try {
					connFromApp.shutdown(); // this will also close socket
				} catch (IOException ignore) {
				}
				e.printStackTrace();
			}
		} while (connFromApp.isOpen());
	}

	public void handle(HttpRequest request, HttpResponse response, HttpContext context)
			throws HttpException, IOException {
		DefaultBHttpClientConnection connToDest = new DefaultBHttpClientConnection(bufferSize, fragmentSizeHint, null,
				null, MessageConstraints.DEFAULT, StrictContentLengthStrategy.INSTANCE,
				StrictContentLengthStrategy.INSTANCE, null, null);
		final HttpProcessor httpproc = HttpProcessorBuilder.create().add(new RequestContent())
				.add(new RequestTargetHost()).add(new RequestConnControl()).add(new RequestUserAgent("Test/1.1"))
				.add(new RequestExpectContinue(true)).build();

		final HttpRequestExecutor httpexecutor = new HttpRequestExecutor();

		final BasicConnPool pool = new BasicConnPool(new BasicConnFactory());
		pool.setDefaultMaxPerRoute(2);
		pool.setMaxTotal(2);

		HttpHost[] targets = { new HttpHost("www.google.com", 80), new HttpHost("www.yahoo.com", 80),
				new HttpHost("www.apache.com", 80) };

		class WorkerThread extends Thread {

			private final HttpHost target;

			WorkerThread(final HttpHost target) {
				super();
				this.target = target;
			}

			@Override
			public void run() {
				ConnectionReuseStrategy connStrategy = DefaultConnectionReuseStrategy.INSTANCE;
				try {
					Future<BasicPoolEntry> future = pool.lease(this.target, null);

					boolean reusable = false;
					BasicPoolEntry entry = future.get();
					try {
						HttpClientConnection conn = entry.getConnection();
						HttpCoreContext coreContext = HttpCoreContext.create();
						coreContext.setTargetHost(this.target);

						BasicHttpRequest request = new BasicHttpRequest("GET", "/");
						System.out.println(">> Request URI: " + request.getRequestLine().getUri());

						httpexecutor.preProcess(request, httpproc, coreContext);
						HttpResponse response = httpexecutor.execute(request, conn, coreContext);
						httpexecutor.postProcess(response, httpproc, coreContext);

						System.out.println("<< Response: " + response.getStatusLine());
						System.out.println(EntityUtils.toString(response.getEntity()));

						reusable = connStrategy.keepAlive(response, coreContext);
					} catch (IOException ex) {
						throw ex;
					} catch (HttpException ex) {
						throw ex;
					} finally {
						if (reusable) {
							System.out.println("Connection kept alive...");
						}
						pool.release(entry, reusable);
					}
				} catch (Exception ex) {
					System.out.println("Request to " + this.target + " failed: " + ex.getMessage());
				}
			}

		}
		;
	}
}
