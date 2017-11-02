/*
 *    This file is part of ReadonlyREST.
 *
 *    ReadonlyREST is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    ReadonlyREST is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with ReadonlyREST.  If not, see http://www.gnu.org/licenses/
 */

package org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.Group;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleExitResult;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleNotConfiguredException;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.SyncRule;
import org.elasticsearch.plugin.readonlyrest.oauth.OAuthToken;
import org.elasticsearch.plugin.readonlyrest.security.RuleRole;
import org.elasticsearch.plugin.readonlyrest.wiring.requestcontext.RequestContext;

/**
 * A GroupsSyncRule checks if a request containing Basic Authentication credentials
 * matches a user in one of the specified groups.
 *
 * @author Christian Henke (maitai@users.noreply.github.com)
 */
public class GroupsSyncRule extends SyncRule {

	private final String group;
	private final Pattern pattern;

	private static final Map<String, String> SpecialUsr = createSpecialUsrs();
    private static Map<String, String> createSpecialUsrs()
    {
        Map<String,String> myMap = new HashMap<String,String>();
        myMap.put(Group.KIBANA, "USR_KIBANA");
        myMap.put(Group.INDEXER, "Ind3xeur");
        return myMap;
    }

	public GroupsSyncRule(Group grp) throws RuleNotConfiguredException {
		super();

		if (grp == null || grp.getGroup() == null || grp.getGroup().trim().isEmpty())
			throw new RuleNotConfiguredException();
		this.group = grp.getGroup().trim();

		// Wildcard group, ie Viewer_DR*
		if (this.group.contains("*")) {
			String regex = "^" + ("\\Q" + this.group + "\\E").replace("*", "\\E.*\\Q") + "$";
			this.pattern = Pattern.compile(regex);
		} else {
			this.pattern = null;
		}
	}

	public static Optional<GroupsSyncRule> fromSettings(Settings s, Group grp) {
		try {
			return Optional.of(new GroupsSyncRule(grp));
		} catch (RuleNotConfiguredException ignored) {
			return Optional.empty();
		}
	}

	@Override
	public RuleExitResult match(RequestContext rc) {
		OAuthToken token = rc.getToken();
		if (token == null) {
			String special = SpecialUsr.get(this.group);
			if (special == null) 
				return NO_MATCH;
			
			if (!rc.getLoggedInUser().isPresent())
				return NO_MATCH;

			String username = rc.getLoggedInUser().get().getId();
			if (special.equals(username)) {
				rc.setRuleRole(new RuleRole(this.group, this.group));
				return  MATCH;
			}

			return NO_MATCH;
		} else if (token.getRoles() == null) {
			return NO_MATCH;
		} else {
			// Check get first role containing the group
			for (String role : token.getRoles()) {
				if ( this.pattern != null ) {
					Matcher m = this.pattern.matcher(role);
					if (m == null) {
						continue;
					  }
					  if (m.find()) {
						rc.setRuleRole(new RuleRole(this.group, role));
						return MATCH;
					  }
				} else if ( this.group.equals(role) ) {
					rc.setRuleRole(new RuleRole(this.group, role));
					return MATCH;
				}
			}
			return NO_MATCH;
		}
	}
}
