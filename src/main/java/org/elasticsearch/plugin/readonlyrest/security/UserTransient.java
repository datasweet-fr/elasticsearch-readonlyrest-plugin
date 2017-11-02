package org.elasticsearch.plugin.readonlyrest.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

import org.elasticsearch.plugin.readonlyrest.acl.blocks.Group;
import org.elasticsearch.plugin.readonlyrest.oauth.OAuthToken;
import org.elasticsearch.plugin.readonlyrest.wiring.requestcontext.RequestContext;

public class UserTransient implements Serializable {
    /**
	 * 
	 */
	private static final long serialVersionUID = -8866625802695512997L;
	private final String _username;
    private final String _ruleId;
    private final String _role;
    private Boolean isKibana = Boolean.FALSE;
    private Boolean isAdmin = Boolean.FALSE;
    private Boolean isIndexer = Boolean.FALSE;
    private static UserTransient Kibana = new UserTransient("USR_KIBANA", Group.KIBANA, Group.KIBANA);
    private static UserTransient Indexer = new UserTransient("USR_INDEXER", Group.INDEXER, Group.INDEXER);

    public static UserTransient CreateFromRequestContext(RequestContext rc) {
        if (rc == null)
            throw new IllegalArgumentException("You need to provide the request context.");

        if (!rc.getRuleRole().isPresent()) {
            throw new IllegalStateException("Unable to extract rule and role from request context.");
        }
        RuleRole rr = rc.getRuleRole().get();
        OAuthToken token = rc.getToken();

        if (token == null) {
            if (!rc.getLoggedInUser().isPresent())
                throw new IllegalStateException("Unable to extract user from request context.");

            if (Group.KIBANA.equals(rr.getRuleId())) {
            	Kibana.isKibana = Boolean.TRUE;
            	return Kibana;
            }

            if (Group.INDEXER.equals(rr.getRuleId())) {
            	Indexer.isIndexer = Boolean.TRUE;
            	return Indexer;
            }

            return new UserTransient(rc.getLoggedInUser().get().getId(), rr.getRuleId(), rr.getRoleLinked());
        } else {
            // Check the role linked is contained in token
            if (!token.getRoles().contains(rr.getRoleLinked())) {
                throw new IllegalStateException("Unable to merge role from request context & token.");
            }

            return new UserTransient(token.getPreferredUsername(), rr.getRuleId(), rr.getRoleLinked());
        }
    }

    private UserTransient(String username, String ruleId, String role) {
        this._username = username;
        this._ruleId = ruleId;
        this._role = role;
    }

    public String getUsername() {
        return this._username;
    }

    public String getRuleId() {
        return this._ruleId;
    }

    public String getRole() {
        return this._role;
    }

    public boolean isAdmin() {
        return Group.ADMIN.equals(this._ruleId) && Group.ADMIN.equals(this._role);
    }

    public Boolean isKibana() {
        return this.isKibana;
    }

    public Boolean isIndexer() {
        return this.isIndexer;
    }


    @Override
    public String toString() {
        return "{ USR: " + this._username + ", ADM: " + isAdmin() + ", KIB: " + isKibana() + ", IDX: " + isIndexer()
                + ", RULE: " + this._ruleId
                + ", ROLE: " + this._role
                + "}";
    }
    
    public String serialize() {
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos;
		try {
			oos = new ObjectOutputStream(baos);
			oos.writeObject(this);
	        oos.close();
		} catch (IOException e) {
			return null;
		}
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
    
    public static UserTransient Deserialize(String userTransientEncoded) {
    	UserTransient userTransient = null;
    	byte [] data = Base64.getDecoder().decode(userTransientEncoded);
        ObjectInputStream ois;
		try {
			ois = new ObjectInputStream(new ByteArrayInputStream(data));
			Object o  = ois.readObject();
			if (o instanceof UserTransient) {
				userTransient = (UserTransient) o;
			}
	        ois.close();
		} catch (IOException e) {
			throw new IllegalStateException("Couldn't extract userTransient from threadContext.");
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException("Couldn't extract userTransient from threadContext.");
		}
		return userTransient;

    }
}