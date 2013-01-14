/**
 *  Created on  : 20/06/2012
 *  Author      : Ing. Javier Silva Pérez - [javier]
 *  Description :
 *  	
 */
package cinvestav.android.pki.utils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;

import android.os.Environment;
import android.util.Log;

/**
 * Utility for wraps the loggin capabilities for the application, so this could
 * be independent of the used logger
 * 
 * @author Ing. Javier Silva Pérez - [javier]
 * @since 20/06/2012
 * @version 1.0
 */
public class LogUtil {
	private String TAG = "";

	/**
	 * Set the class that invokes the log, so its name appears in log entry
	 * 
	 * @param clazz
	 */
	public LogUtil(Class<?> clazz) {
		TAG = clazz.getName();
	}

	/**
	 * Set the tag for the logs entries
	 * 
	 * @param logTag
	 */
	public LogUtil(String logTag) {
		TAG = logTag;
	}

	/**
	 * Logs the message as with error level
	 * 
	 * @param message
	 *            Message to be logged
	 */
	public void error(Object message) {
		Log.e(TAG, message.toString());
	}

	/**
	 * Logs a message and its throwable
	 * 
	 * @param message
	 *            Message to be logged
	 * @param t
	 *            Throwable of the message
	 */
	public void error(Object message, Throwable t) {
		Log.e(TAG, message.toString(), t);
	}

	/**
	 * Logs the message as with debug level
	 * 
	 * @param message
	 *            Message to be logged
	 */
	public void debug(Object message) {
		Log.d(TAG, message.toString());
	}

	/**
	 * Logs a message and its throwable
	 * 
	 * @param message
	 *            Message to be logged
	 * @param t
	 *            Throwable of the message
	 */
	public void debug(Object message, Throwable t) {
		Log.d(TAG, message.toString(), t);

	}

	/**
	 * Logs the message as with fatal level
	 * 
	 * @param message
	 *            Message to be logged
	 */
	public void fatal(Object message) {
		Log.e(TAG, message.toString());
	}

	/**
	 * Logs a message and its throwable
	 * 
	 * @param message
	 *            Message to be logged
	 * @param t
	 *            Throwable of the message
	 */
	public void fatal(Object message, Throwable t) {
		Log.e(TAG, message.toString(), t);
	}

	/**
	 * Logs the message as with info level
	 * 
	 * @param message
	 *            Message to be logged
	 */
	public void info(Object message) {
		Log.i(TAG, message.toString());
	}

	/**
	 * Logs a message and its throwable
	 * 
	 * @param message
	 *            Message to be logged
	 * @param t
	 *            Throwable of the message
	 */
	public void info(Object message, Throwable t) {
		Log.i(TAG, message.toString(), t);
	}

	/**
	 * Logs the message as with trace level
	 * 
	 * @param message
	 *            Message to be logged
	 */
	public void trace(Object message) {
		Log.v(TAG, message.toString());
	}

	/**
	 * Logs a message and its throwable
	 * 
	 * @param message
	 *            Message to be logged
	 * @param t
	 *            Throwable of the message
	 */
	public void trace(Object message, Throwable t) {
		Log.v(TAG, message.toString(), t);
	}

	/**
	 * Logs the message as with warn level
	 * 
	 * @param message
	 *            Message to be logged
	 */
	public void warn(Object message) {
		Log.w(TAG, message.toString());
	}

	/**
	 * Logs a message and its throwable
	 * 
	 * @param message
	 *            Message to be logged
	 * @param t
	 *            Throwable of the message
	 */
	public void warn(Object message, Throwable t) {
		Log.w(TAG, message.toString(), t);
	}

	/**
	 * Writes the log entry to a file
	 * 
	 * @param text
	 *            Text to append to the file
	 * @param fileName
	 *            File name
	 */
	public void toFile(String text, String fileName) {
		File logFile = new File(Environment.getExternalStorageDirectory()
				+ "/cryptoTestTiming/" + fileName + ".log");
		if (!logFile.getParentFile().exists()) {
			logFile.getParentFile().mkdir();
		}
		if (!logFile.exists()) {
			try {
				logFile.createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		try {
			// BufferedWriter for performance, true to set append to file flag
			BufferedWriter buf = new BufferedWriter(new FileWriter(logFile,
					true));
			buf.append(new Date() +": "+text);
			buf.newLine();
			buf.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
