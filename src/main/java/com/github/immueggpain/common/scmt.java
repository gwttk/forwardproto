package com.github.immueggpain.common;

/** scmt = shortcut for multi-threading */
public final class scmt {

	/** good to use */
	public static Thread execAsync(String name, Runnable runnable) {
		Thread t = new Thread(runnable, name);
		t.start();
		return t;
	}

	/** ignore InterruptedException */
	public static void sleep(long millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException ignore) {
		}
	}

	/** ignore InterruptedException */
	public static void join(Thread thread) {
		try {
			thread.join();
		} catch (InterruptedException ignore) {
		}
	}

}
