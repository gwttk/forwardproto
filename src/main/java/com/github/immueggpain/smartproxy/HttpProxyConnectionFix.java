package com.github.immueggpain.smartproxy;

import java.io.IOException;

import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.protocol.HttpContext;

public class HttpProxyConnectionFix implements HttpRequestInterceptor {

	@Override
	public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
		Header pc = request.getLastHeader("Proxy-Connection");
		if (pc == null)
			return;
		String pcv = pc.getValue();
		request.removeHeaders("Proxy-Connection");
		request.removeHeaders("Connection");
		request.setHeader("Connection", pcv);
	}

}
