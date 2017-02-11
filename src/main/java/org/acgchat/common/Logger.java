package org.acgchat.common;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by NEOPETS on 18/1/2017.
 */
public abstract class Logger {

    protected SimpleDateFormat simpleDateFormat;

    public Logger() {
        simpleDateFormat = new SimpleDateFormat("HH:mm:ss");
    }

    /**
     * Log the message out to the console
     * @param type The message type
     * @param message The message to print
     */
    public void log(String type, String message) {
        System.out.println(simpleDateFormat.format(new Date()) + " - [" + type + "] " + message);
    }

    /**
     * Prints out a [INFO] message
     * @param message The message to print
     */
    public void info(String message) {
        log("INFO", message);
    }

    /**
     * Prints out a [DEBUG] message.
     * Intended use for development.
     * @param message The message to print
     */
    public void debug(String message) {
        log("DEBUG", message);
    }

    /**
     * Prints out a [CHAT] message
     * @param message The message to print
     */
    public void chat(String message) {
        log("CHAT", message);
    }

    /**
     * Prints out a [WARNING] message
     * @param message The message to print
     */
    public void warning(String message) {
        log("WARNING", message);
    }

    /**
     * Prints out a [ERROR] message
     * @param message The message to print
     */
    public void error(String message) {
        log("ERROR", message);
    }

}
