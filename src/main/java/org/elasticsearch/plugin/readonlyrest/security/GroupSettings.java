package org.elasticsearch.plugin.readonlyrest.security;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.MatcherWithWildcards;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleNotConfiguredException;

public class GroupSettings {

    // NO time to adapt : see VariableManager
    private static final char ESCAPE_CHAR = '@';
    private static final char DELIMITER_BEGIN_CHAR = '{';
    private static final char DELIMITER_END_CHAR = '}';
    private static final String VAR_DETECTOR = new StringBuilder(2).append(ESCAPE_CHAR).append(DELIMITER_BEGIN_CHAR).toString();

    private final String ruleId;
    private final MatcherWithWildcards mindexes;
    private final String filter;
    private final boolean hasFilter;;

    private final Map<String, Boolean> cacheIndexes;
    private final Map<String, String> cacheFilters;

    private GroupSettings(String ruleId, String[] indexes, String filter) {
        this.ruleId = ruleId;
        if (indexes == null || indexes.length == 0) {
            this.mindexes =  null;
        }
        else {
            HashSet<String> set = new HashSet<>();
            Collections.addAll(set, indexes);
            this.mindexes= new MatcherWithWildcards(set);
        }
        this.filter = (filter == null ? null : filter.trim());
        this.hasFilter = (this.filter != null && !this.filter.isEmpty());

        this.cacheIndexes = new HashMap<String, Boolean>();
        this.cacheFilters = new HashMap<String, String>();
    }

    public String getRuleId() {
        return this.ruleId;
    }

    public boolean matchIndex(String indexName) {
        Boolean exists = this.cacheIndexes.get(indexName);
        if (exists != null)
            return exists;

        // Compute and add in cache
        exists = this.mindexes.match(indexName);
        this.cacheIndexes.put(indexName, exists);
        return exists;
    }

    public String getFilter(RuleRole ruleRole) {
        if (!this.hasFilter) 
            return null;

        if (ruleRole == null)
            return null;

        if (!this.ruleId.equals(ruleRole.getRuleId()))
            return null;

        String f = this.cacheFilters.get(ruleRole.getRoleLinked());
        if (f != null)
            return f;

        // Compute
        List<String> captures = ruleRole.substract();
        Map<String, String> map = new HashMap<String, String>();
        if (captures != null) {
            for (String c : captures) {
                map.put("1", c);
            }
        }
        map.put("role", ruleRole.getRoleLinked());
        f = replace(map, this.filter);
        this.cacheFilters.put(ruleRole.getRoleLinked(), f);
        return f;
    }

    public static GroupSettings CreateFromSettings(Settings s) throws RuleNotConfiguredException {
        return new GroupSettings(
            s.get("group"), 
            s.getAsArray("indices"), 
            s.get("filters")
        );
    }

    /**
    * Uber-fast regex-free template replacer
    *
    * @param map replacements pool
    * @param str haystack string
    * @return replaced or unchanged string.
    */
    private String replace(Map<String, String> map, String str) {
        StringBuilder sb = new StringBuilder();
        char[] strArray = str.toCharArray();
        int i = 0;
        while (i < strArray.length - 1) {
            if (strArray[i] == ESCAPE_CHAR && strArray[i + 1] == DELIMITER_BEGIN_CHAR) {
                i = i + 2;
                int begin = i;
                while (strArray[i] != DELIMITER_END_CHAR)
                    ++i;
                String key = str.substring(begin, i++);
                String replacement = map.get(key);
                if (replacement == null) {
                    replacement = VAR_DETECTOR + key + DELIMITER_END_CHAR;
                }
                sb.append(replacement);
            } else {
                sb.append(strArray[i]);
                ++i;
            }
        }
        if (i < strArray.length)
            sb.append(strArray[i]);
        return sb.toString();
    }
}