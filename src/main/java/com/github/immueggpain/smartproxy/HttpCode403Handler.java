package com.github.immueggpain.smartproxy;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.protocol.HttpContext;

public class HttpCode403Handler extends BaseHandler {

	public void handleGet(HttpRequest request, HttpResponse response, HttpContext context, String url)
			throws Exception {

		String htmlString = "";

		StringEntity entity = new StringEntity(htmlString, ContentType.create("text/plain", "UTF-8"));

		response.setStatusCode(HttpStatus.SC_FORBIDDEN);
		response.setEntity(entity);
	}

}
