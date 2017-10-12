package org.elasticsearch.plugin.readonlyrest.security;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RuleRole {

    private final String ruleId;
    private final String forRole;

    // Simple class to associate a rule Id to an oauth role.
    public RuleRole(String ruleId, String forRole) {
        this.ruleId = ruleId;
        this.forRole = forRole;
    }

    public String getRuleId() {
        return this.ruleId;
    }

    public String getRoleLinked() {
        return this.forRole;
    }

    public List<String> substract() {
        Pattern p = Pattern.compile(this.ruleId.replaceAll("\\*", "(\\.+)"));
        Matcher m = p.matcher(this.forRole);
        if (!m.matches() || m.groupCount()  == 0) {
            return null;
        }
        List<String> captureList = new ArrayList<String>();
        for (int i = 1; i <= m.groupCount(); i++) {
            captureList.add(m.group(i));
        }
        return captureList;
    }
}