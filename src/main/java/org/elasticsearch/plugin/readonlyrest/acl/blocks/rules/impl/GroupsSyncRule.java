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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.Group;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.Group.TYPE;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleExitResult;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleNotConfiguredException;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.SyncRule;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.User;
import org.elasticsearch.plugin.readonlyrest.oauth.OAuthToken;
import org.elasticsearch.plugin.readonlyrest.wiring.requestcontext.RequestContext;

/**
 * A GroupsSyncRule checks if a request containing Basic Authentication credentials
 * matches a user in one of the specified groups.
 *
 * @author Christian Henke (maitai@users.noreply.github.com)
 */
public class GroupsSyncRule extends SyncRule {

  //private final List<User> users;
  private final List<String> groups;
  private  boolean hasReplacements = false;
  private String kibanaGroup = "Kibana";
  private String adminGroup = "Admin";
  
  public GroupsSyncRule(Settings s, List<User> userList, Group grp) throws RuleNotConfiguredException {
    super();

    //users = userList;
    String[] pGroups = s.getAsArray(this.getKey());

    if (pGroups != null && pGroups.length > 0) {
		List<String> grps = new ArrayList<>();
		grps.addAll(Arrays.asList(pGroups));
		List<String> groups = Arrays.asList(pGroups);
		if (groups.contains(kibanaGroup) || groups.contains(adminGroup))
			this.groups = groups;
		else {
			List<String> tmp = new ArrayList<>();
			if (grp != null) {
				TYPE type = grp.getType();
				grps.forEach(item -> {
					if (item.toLowerCase().equals(type.toString().toLowerCase()))
						tmp.add(grp.getGroup());
					//TODO:  ??? not sure
					if(item != null && item.contains("@")){
						hasReplacements = true;
					}
				});
			}
			grps.addAll(tmp);
			this.groups = grps;
		}
	} else {
		throw new RuleNotConfiguredException();
	}
  }

  public static Optional<GroupsSyncRule> fromSettings(Settings s, List<User> userList, Group grp) {
    try {
      return Optional.of(new GroupsSyncRule(s, userList, grp));
    } catch (RuleNotConfiguredException ignored) {
      return Optional.empty();
    }
  }

  @Override
  public RuleExitResult match(RequestContext rc) {
    	OAuthToken token = rc.getToken();
    	List<String> commonGroups = new ArrayList<>(this.groups);
		if (commonGroups.contains(kibanaGroup) && token == null)
			return MATCH;
		if (commonGroups == null || commonGroups.isEmpty() || token == null || token.getRoles() == null)
			return NO_MATCH;
		commonGroups.retainAll(token.getRoles());
		// Using a set to remove all duplicates
		Set<String> commonGroupsSet = new HashSet<>(commonGroups);
		commonGroupsSet.retainAll(token.getRoles());
		if (!commonGroupsSet.isEmpty() && token.getRoles().contains(adminGroup))
			return MATCH;
		else if (commonGroupsSet.size() == token.getRoles().size())
			return MATCH;
		return NO_MATCH;
  }

}
