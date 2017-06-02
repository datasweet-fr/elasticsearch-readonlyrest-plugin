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

import java.util.Calendar;
import java.util.Date;
import java.util.Optional;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.readonlyrest.ConfigurationHelper;
import org.elasticsearch.plugin.readonlyrest.acl.LoggedUser;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleExitResult;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleNotConfiguredException;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.SyncRule;
import org.elasticsearch.plugin.readonlyrest.oauth.OAuthToken;
import org.elasticsearch.plugin.readonlyrest.utils.OAuthUtils;
import org.elasticsearch.plugin.readonlyrest.wiring.requestcontext.RequestContext;

public class TokenSyncRule extends SyncRule {
    private final Logger logger = Loggers.getLogger(getClass());
//    private final Boolean needToCheckRule;
    private final String cookieSecret;
    private final String cookieName;
    private final String tokenClientId;
    private final String tokenSecret;
    
    public TokenSyncRule(Settings s, ConfigurationHelper conf) throws RuleNotConfiguredException {
        super();
        if (s.get("auth_oauth", "").equals(""))
        	throw new RuleNotConfiguredException();
        cookieSecret = conf.cookieSecret;
        cookieName = conf.cookieName;
        tokenClientId = conf.tokenClientId;
        tokenSecret = conf.tokenSecret;
    }

    public static Optional<TokenSyncRule> fromSettings(Settings s, ConfigurationHelper conf) {
		try {
			return Optional.of(new TokenSyncRule(s, conf));
		} catch (RuleNotConfiguredException e) {
			return Optional.empty();
		}
	}

	@Override
	public RuleExitResult match(RequestContext rc) {
		OAuthToken token = OAuthUtils.getOAuthToken(rc.getHeaders(), this.cookieName, this.cookieSecret, this.tokenClientId, this.tokenSecret);
		rc.setToken(token);
		token = rc.getToken();
		if (token == null) {
			rc.setLoggedInUser(new LoggedUser("Kibana"));
			return NO_MATCH;
		}
		boolean valid = true;
		valid &= OAuthUtils.verifyTokenIntegrity(token, token.getPublicKey());
		Date expDate = token.getExp();
		Date now = Calendar.getInstance().getTime();
		valid &= expDate.after(now);
		rc.getToken().setValid(valid);
		rc.setLoggedInUser(new LoggedUser(token.getPreferredUsername()));
		return valid ? MATCH : NO_MATCH;
	}
}
