package side;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import side.snort.SnortMatcher;
import side.snort.SnortParser;
import side.snort.Variables;
import org.pcap4j.core.PcapHandle;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;

public class Main {

    public static void main(String[] args) {
        setupLogger();

        setupVariables();

        SnortParser snort = new SnortParser();
        try {
            snort.parse(Paths.get("snort.txt"));
        } 
        catch (Exception e) {
            e.printStackTrace();
            System.exit(12);
        }

        Ids ids = new Ids(new SnortMatcher(snort));
        ids.start();
        try {
            ids.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void setupVariables() {
        Variables.define("$HOME_NET", "192.168.43.0/16");
        Variables.define("$EXTERNAL_NET", "!$HOME_NET");
        Variables.define("$SMTP_SERVERS", "ANY");
        Variables.define("$HTTP_SERVERS", "ANY");
        Variables.define("$TELNET_SERVERS", "ANY");
        Variables.define("$SQL_SERVERS", "ANY");
        Variables.define("$DNS_SERVERS", "ANY");
    }

    private static void setupLogger() {
        LoggerContext logCtx = (LoggerContext) LoggerFactory.getILoggerFactory();

        PatternLayoutEncoder logEncoder = new PatternLayoutEncoder();
        logEncoder.setContext(logCtx);
        logEncoder.setPattern("%-12date{YYYY-MM-dd HH:mm:ss.SSS} %-5level - %msg%n");
        logEncoder.start();

        ConsoleAppender<ILoggingEvent> logConsoleAppender = new ConsoleAppender<>();
        logConsoleAppender.setContext(logCtx);
        logConsoleAppender.setName("console");
        logConsoleAppender.setEncoder(logEncoder);
        logConsoleAppender.start();

        logEncoder = new PatternLayoutEncoder();
        logEncoder.setContext(logCtx);
        logEncoder.setPattern("%-12date{YYYY-MM-dd HH:mm:ss.SSS} %-5level - %msg%n");
        logEncoder.start();

        Logger log = logCtx.getLogger("Main");
        log.setAdditive(false);
        log.setLevel(Level.INFO);
        log.addAppender(logConsoleAppender);

        Logger pcapLog = logCtx.getLogger(PcapHandle.class);
        pcapLog.setAdditive(false);
        pcapLog.setLevel(Level.WARN);
        pcapLog.addAppender(logConsoleAppender);
    }
}
