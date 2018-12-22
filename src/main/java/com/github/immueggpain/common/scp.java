package com.github.immueggpain.common;

import java.io.IOException;
import java.nio.charset.Charset;
import org.apache.commons.io.IOUtils;

/** scp = shortcut for process operation */
public final class scp {

	public static ProcessResult collectResult(Process proc) throws IOException {
		ProcessResult r = new ProcessResult();
		r.stdout = IOUtils.toString(proc.getInputStream(), Charset.defaultCharset());
		r.stderr = IOUtils.toString(proc.getErrorStream(), Charset.defaultCharset());
		try {
			proc.waitFor();
		} catch (InterruptedException e) {
			// ignore
		}
		r.rcode = proc.exitValue();
		return r;
	}

	public static class ProcessResult {
		public String stdout;
		public String stderr;
		public int rcode;
	}

}
