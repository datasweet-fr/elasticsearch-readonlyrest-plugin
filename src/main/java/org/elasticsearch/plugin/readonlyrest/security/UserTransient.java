package org.elasticsearch.plugin.readonlyrest.security;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.Group;
import org.elasticsearch.plugin.readonlyrest.oauth.OAuthToken;
import org.elasticsearch.plugin.readonlyrest.wiring.requestcontext.RequestContext;

public class UserTransient {
    private final String _username;
    private final List<String> _captureList;
    private final List<String> _roles;

    private static UserTransient Kibana = new UserTransient("Kibana", null, null);
    private static UserTransient Indexer = new UserTransient("Indexer", null, null);

    public static UserTransient CreateFromRequestContext(RequestContext rc) {
        if (rc == null)
            throw new IllegalArgumentException("You need to provide the request context.");

        OAuthToken token = rc.getToken();

        if (token == null) {
            if (!rc.getLoggedInUser().isPresent())
                throw new IllegalArgumentException("Unable to extract user from request context.");

            if (rc.getGroupRule().equals(Group.KIBANA))
                return Kibana;

            if (rc.getGroupRule().equals(Group.INDEXER))
                return Indexer;

            List<String> roles = new ArrayList<String>(1);
            roles.add(rc.getGroupRule());
            return new UserTransient(rc.getLoggedInUser().get().getId(), roles, null);
        } else {
            return new UserTransient(token.getPreferredUsername(), token.getRoles(), rc.getGroupRule());
        }
    }

    private UserTransient(String username, List<String> roles, String ruleGroup) {
        this._username = username;
        this._roles = roles;
        this._captureList = createCaptureList(roles, ruleGroup);
    }

    public String getUsername() {
        return this._username;
    }

    public List<String> getGroups() {
        return this._captureList;
    }

    public List<String> getRoles() {
        return this._roles;
    }

    public boolean isAdmin() {
        return this._roles != null && this._roles.contains(Group.ADMIN);
    }

    public boolean isKibana() {
        return this == Kibana;
    }

    public boolean isIndexer() {
        return this == Indexer;
    }

    // A REVOIR
    private List<String> createCaptureList(List<String> roles, String ruleGroup) {
        if (ruleGroup == null || ruleGroup.isEmpty()) {
            return null;
        }

        for (String role : roles) {
            // \d for digit [0-9]
            // Will replace all the group in the config where there is a * in the name (D*, DR*, C*, ...)
            // Admin, Editor, Viewer, ... won't be impacted
            String pattern = ruleGroup.replaceAll("\\*", "(\\.+)").replaceAll("\\?", "(\\.)");
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(role);
            boolean b = m.matches();
            if (b) {
                // Get the capture (for (D*, D01) returns 01) so we
                // can replace it when we'll use the filters later
                if (m.groupCount() > 0) {
                    List<String> captureList = new ArrayList<>();
                    for (int i = 1; i <= m.groupCount(); i++) {
                        captureList.add(m.group(i));
                    }
                    return captureList;
                }
                return null;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return "{ USR: " + this._username + ", ADM: " + isAdmin() + ", KIB: " + isKibana() + ", IDX: " + isIndexer()
                + ", ROLES: [" + (this._roles != null ? String.join(",", this._roles) : "") + "], CPTS: ["
                + (this._captureList != null ? String.join(",", this._captureList) : "") + "]}";
    }
}