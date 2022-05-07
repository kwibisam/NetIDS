package side.snort;


public final class ParserUtils {
    private ParserUtils() {
    }

    public static MinMaxValue minMaxParser(String toParse) throws Exception {
        if (toParse.contains("<>") || toParse.contains("<=>")) {
            String[] parts = toParse.split("<=?>");
            if (parts.length != 2) {
                throw new Exception("Could not parse <> syntax from " + toParse);
            }
            return new MinMaxValue(intFrom(parts[0]), intFrom(parts[1]), toParse.contains("<=>"));
        }
        assertNotEmpty(toParse);
        char prefix = toParse.charAt(0);
        switch (prefix) {
            case '>':
                return new MinMaxValue(intFrom(toParse.substring(1)), null, false);
            case '<':
                return new MinMaxValue(null, intFrom(toParse.substring(1)), false);
        }
        int i = intFrom(toParse);
        return new MinMaxValue(i, i, true);
    }

    private static void assertNotEmpty(String value) throws Exception {
        if (value.isBlank()) {
            throw new Exception("Nothing to parse");
        }
    }

    private static Integer intFrom(String s) throws Exception {
        assertNotEmpty(s);
        try {
            return Integer.valueOf(s);
        } catch (NumberFormatException e) {
            throw new Exception("Could not parse number from " + s, e);
        }
    }

    public static class MinMaxValue {
        private final Integer min;
        private final Integer max;
        private final boolean includes;

        public MinMaxValue(Integer min,
                           Integer max,
                           boolean includes) {
            this.min = min;
            this.max = max;
            this.includes = includes;
        }

        public Integer getMin() {
            return min;
        }

        public Integer getMax() {
            return max;
        }

        public boolean match(int target) {
            if (min != null && target < min) {
                return false;
            }
            if (min != null && target == min && !includes) {
                return false;
            }
            if (max != null && target > max) {
                return false;
            }
            if (max != null && target == max && !includes) {
                return false;
            }
            return true;
        }
    }
}
