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

    public void log(String type, String message) {
        System.out.println(simpleDateFormat.format(new Date()) + " - [" + type + "] " + message);
    }

    public void info(String message) {
        log("INFO", message);
    }

    public void chat(String message) {
        log("CHAT", message);
    }

    public void warning(String message) {
        log("WARNING", message);
    }

    public void error(String message) {
        log("ERROR", message);
    }

}
