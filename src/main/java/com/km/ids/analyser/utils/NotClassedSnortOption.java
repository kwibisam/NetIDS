package com.km.ids.analyser.utils;

/**
 *
 * @author Kwibisa Mwene
 */
public class NotClassedSnortOption extends NotImplementedSnortOption {
    public NotClassedSnortOption(SnortOptionType type, String value) {
        super(type, value);
        //logger.warn("Snort option without class: {}", this);
    }
}
