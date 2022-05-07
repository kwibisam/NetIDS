package com.km.ids.analyser.snort;

import com.km.ids.data.PacketInfo;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class SnortMatcher {
    private final Map<SnortProtocol, List<SnortRule>> rules;

    public SnortMatcher(SnortParser parser) {
        rules = parser.getRules();
    }

    public List<SnortRule> match(PacketInfo packetInfo) throws Exception {

        SnortProtocol protocol = packetInfo.protocol();
        List<SnortRule> ruleList = rules.get(protocol);
        if (ruleList == null) {
            ruleList = rules.getOrDefault(SnortProtocol.all, new LinkedList<>());
        } 
        else {
            ruleList.addAll(rules.getOrDefault(SnortProtocol.all, Collections.emptyList()));
        }
        if (ruleList == null) {
            return Collections.emptyList();
        }

        List<SnortRule> matched = new LinkedList<>();
        for (SnortRule rule : ruleList) {
            if (rule.match(packetInfo)) {
                matched.add(rule);
            }
        }
        return matched;
    }
}
