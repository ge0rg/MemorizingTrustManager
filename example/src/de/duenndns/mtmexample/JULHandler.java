package de.duenndns.mtmexample;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringBufferInputStream;
import java.io.StringWriter;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import android.util.Log;

/**
 * A <code>java.util.logging</code> (JUL) Handler for Android.
 * <p>
 * If you want fine-grained control over MTM's logging, you can copy this
 * class to your code base and call the static {@link #initialize()} method.
 * </p>
 * <p>
 * This JUL Handler passes log messages sent to JUL to the Android log, while
 * keeping the format and stack traces of optionally supplied Exceptions. It
 * further allows to install a {@link DebugLogSettings} class via
 * {@link #setDebugLogSettings(DebugLogSettings)} that determines whether JUL log messages of
 * level {@link java.util.logging.Level#FINE} or lower are logged. This gives
 * the application developer more control over the logged messages, while
 * allowing a library developer to place debug log messages without risking to
 * spam the Android log.
 * </p>
 * <p>
 * If there are no {@code DebugLogSettings} configured, then all messages sent
 * to JUL will be logged.
 * </p>
 * 
 * @author Florian Schmaus
 * 
 */
@SuppressWarnings("deprecation")
public class JULHandler extends Handler {

	/** Implement this interface to toggle debug logging.
	 */
	public interface DebugLogSettings {
		public boolean isDebugLogEnabled();
	}

	private static final String CLASS_NAME = JULHandler.class.getName();

	/**
	 * The global LogManager configuration.
	 * <p>
	 * This configures:
	 * <ul>
	 * <li> JULHandler as the default handler for all log messages
	 * <li> A default log level FINEST (300). Meaning that log messages of a level 300 or higher a
	 * logged
	 * </ul>
	 * </p>
	 */
	private static final InputStream LOG_MANAGER_CONFIG = new StringBufferInputStream(
// @formatter:off
"handlers = " + CLASS_NAME + '\n' +
".level = FINEST"
);
// @formatter:on

	// Constants for Android vs. JUL debug level comparisons
	private static final int FINE_INT = Level.FINE.intValue();
	private static final int INFO_INT = Level.INFO.intValue();
	private static final int WARN_INT = Level.WARNING.intValue();
	private static final int SEVE_INT = Level.SEVERE.intValue();

	private static final Logger LOGGER = Logger.getLogger(CLASS_NAME);

	/** A formatter that creates output similar to Android's Log.x. */
	private static final Formatter FORMATTER = new Formatter() {
		@Override
		public String format(LogRecord logRecord) {
			Throwable thrown = logRecord.getThrown();
			if (thrown != null) {
				StringWriter sw = new StringWriter();
				PrintWriter pw = new PrintWriter(sw, false);
				pw.write(logRecord.getMessage() + ' ');
				thrown.printStackTrace(pw);
				pw.flush();
				return sw.toString();
			} else {
				return logRecord.getMessage();
			}
		}
	};

	private static DebugLogSettings sDebugLogSettings;
	private static boolean initialized = false;

	public static void initialize() {
		try {
			LogManager.getLogManager().readConfiguration(LOG_MANAGER_CONFIG);
			initialized = true;
		} catch (IOException e) {
			Log.e("JULHandler", "Can not initialize configuration", e);
		}
		if (initialized) LOGGER.info("Initialzied java.util.logging logger");
	}

	public static void setDebugLogSettings(DebugLogSettings debugLogSettings) {
		if (!isInitialized()) initialize();
		sDebugLogSettings = debugLogSettings;
	}

	public static boolean isInitialized() {
		return initialized;
	}

	public JULHandler() {
		setFormatter(FORMATTER);
	}

	@Override
	public void close() {}

	@Override
	public void flush() {}

	@Override
	public boolean isLoggable(LogRecord record) {
		final boolean debugLog = sDebugLogSettings == null ? true : sDebugLogSettings
				.isDebugLogEnabled();

		if (record.getLevel().intValue() <= FINE_INT) {
			return debugLog;
		}
		return true;
	}

	/** JUL method that forwards log records to Android's LogCat. */
	@Override
	public void publish(LogRecord record) {
		if (!isLoggable(record)) return;

		final int priority = getAndroidPriority(record.getLevel());
		final String tag = substringAfterLastDot(record.getSourceClassName());
		final String msg = getFormatter().format(record);

		Log.println(priority, tag, msg);
	}

	/** Helper to convert JUL verbosity levels to Android's Log. */
	private static int getAndroidPriority(Level level) {
		int value = level.intValue();
		if (value >= SEVE_INT) {
			return Log.ERROR;
		} else if (value >= WARN_INT) {
			return Log.WARN;
		} else if (value >= INFO_INT) {
			return Log.INFO;
		} else {
			return Log.DEBUG;
		}
	}

	/** Helper to extract short class names. */
	private static String substringAfterLastDot(String s) {
		return s.substring(s.lastIndexOf('.') + 1).trim();
	}
}
