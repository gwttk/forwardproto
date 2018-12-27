package com.github.immueggpain.smartproxy;

public class HelperFunc {

	/** cull out some useless exception, silent ignore them */
	public static <E extends Exception> void cullException(RunnableE func, Class<E> exceptionClz, String exceptionMsg)
			throws Exception {
		try {
			func.run();
		} catch (Exception e) {
			if (exceptionClz.isInstance(e) && e.getMessage().equals(exceptionMsg)) {
				// ignore
			} else
				throw e;
		}
	}

	@FunctionalInterface
	public interface RunnableE {
		public void run() throws Exception;
	}

}
