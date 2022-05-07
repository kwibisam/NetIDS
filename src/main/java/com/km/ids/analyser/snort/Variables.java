package com.km.ids.analyser.snort;


import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class Variables {
    private static final Object VARIABLE_LOCK = new Object[0];
    private static final Map<String, String> VARIABLES = new HashMap<>();

    public static boolean isVariable(String s) {
        if (s == null || s.isBlank()) {
            return false;
        }
        return s.charAt(0) == '$';
    }

    public static String resolve(String key) throws Exception {
        synchronized (VARIABLE_LOCK) {
            String resolved = VARIABLES.get(key.toLowerCase(Locale.ENGLISH));
            if (resolved == null) {
                throw new Exception("Variable not set: " + key);
            }
            return resolved;
        }
    }

    public static void define(String key, String value) {
        synchronized (VARIABLE_LOCK) {
            VARIABLES.put(key.toLowerCase(Locale.ENGLISH), value.toLowerCase(Locale.ENGLISH));
        }
    }
}
