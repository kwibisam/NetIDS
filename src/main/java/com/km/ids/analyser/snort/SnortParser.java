package com.km.ids.analyser.snort;

import com.km.ids.analyser.utils.PeakableIterator;
import com.km.ids.analyser.utils.SnortOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SnortParser {
    protected static final Logger logger = LoggerFactory.getLogger(SnortParser.class);
    private static final Pattern SNORT_PATTERN = Pattern.compile("([^(<>\\-]*)(->|<>|<-)([^(]*)(\\((.*)\\))?");

    private final Map<SnortProtocol, List<SnortRule>> rules = new HashMap<>();

    public void parse(Path file) throws Exception {
        logger.info("Parsing snort rules from {}...", file);
        try {
            StringBuilder fullLine = new StringBuilder();
            for (String line : Files.readAllLines(file)) {
                line = line.trim();
                if (!line.startsWith("#") && !line.trim().isEmpty()) {
                    if (!line.endsWith("\\")) {
                        process(fullLine.toString() + line);
                        fullLine.setLength(0);
                    } else {
                        fullLine.append(line.substring(0, line.length() - 2).trim()).append(" ");
                    }
                }
            }
            int ruleCount = 0;
            for (List<SnortRule> parsed : rules.values()) {
                ruleCount += parsed.size();
            }
            logger.info("Parsing snort rules from {}... DONE ({} rules in {} protocols)", file, ruleCount, rules.size());
        } 
        catch (RuntimeException e) {
            throw new Exception("Unexpected error", e);
        } 
        catch (IOException e) {
            throw new Exception("Error reading file", e);
        }
    }

    private void process(String line) throws Exception {
        
        try {
            String[] parse = line.split("\\s", 2);
            String actionStr = parse[0];
            String noAction = parse[1];
            SnortAction action = SnortAction.valueOf(actionStr.trim());


            parse = noAction.split("\\s", 2);
            String protocolStr = parse[0];
            String noProtocol = parse[1];
            SnortProtocol protocol = SnortProtocol.all;
            try {
                protocol = SnortProtocol.valueOf(protocolStr.trim());
            } catch (IllegalArgumentException e) {
                noProtocol = noAction;
            }

            Matcher matcher = SNORT_PATTERN.matcher(noProtocol.trim());
            if (!matcher.find()) {
                throw new Exception("Could not parse " + line + "bad layout");
            }
            SnortIp source = new SnortIp(matcher.group(1));
            String direction = matcher.group(2).trim();
            SnortIp destination = new SnortIp(matcher.group(3).trim());

            SnortRule rule = new SnortRule(
                    line,
                    action,
                    protocol,
                    source,
                    direction,
                    destination);
            List<SnortOption> options = Collections.emptyList();
            if (matcher.groupCount() == 5) {
                String optionsStr = matcher.group(5);
                if (optionsStr != null) {
                    options = SnortOption.asSnortOptions(optionsStr.trim(), rule);
                }
            }
            PeakableIterator<SnortOption> iter = new PeakableIterator<>(options.iterator());
            while (iter.hasNext()) {
                iter.next().finalize(iter);
            }
            rule.setOptions(options);

            if (!rules.containsKey(protocol)) {
                rules.put(protocol, new LinkedList<>());
            }
            rules.get(protocol).add(rule);
        } catch (RuntimeException e) {
            throw new Exception("Unexpected error parsing " + line, e);
        }
    }


    public Map<SnortProtocol, List<SnortRule>> getRules() {
        return rules;
    }
}