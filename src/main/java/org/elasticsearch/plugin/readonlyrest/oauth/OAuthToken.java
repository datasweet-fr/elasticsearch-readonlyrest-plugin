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

package org.elasticsearch.plugin.readonlyrest.oauth;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.plugin.readonlyrest.oauth.jiron.Jiron;
import org.elasticsearch.plugin.readonlyrest.oauth.jiron.JironException;
import org.elasticsearch.plugin.readonlyrest.oauth.jiron.JironIntegrityException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import joptsimple.internal.Strings;

public class OAuthToken {

	private String alg;
	private String jti;
	private Date exp;
	private int nbf;
	private Date iat;
	private String iss;
	private String aud;
	private String sub;
	private String typ;
	private String azp;
	private int auth_time;
	private String session_state;
	private String acr;
	private String client_session;
	private ArrayList<String> allowed_origins;
	private ArrayList<String> roles;
	private String name;
	private String preferred_username;
	private boolean isValid;
	private String header;
	private String payload;
	private String signature;
	private String publicKey;

	private final Logger logger = Loggers.getLogger(getClass());

	public String getAlg() {
		return alg;
	}

	public void setAlg(String alg) {
		this.alg = alg;
	}

	public String getJti() {
		return jti;
	}

	public void setJti(String jti) {
		this.jti = jti;
	}

	public Date getExp() {
		return exp;
	}

	public void setExp(Date exp) {
		this.exp = exp;
	}

	public int getNbf() {
		return nbf;
	}

	public void setNbf(int nbf) {
		this.nbf = nbf;
	}

	public Date getIat() {
		return iat;
	}

	public void setIat(Date iat) {
		this.iat = iat;
	}

	public String getIss() {
		return iss;
	}

	public void setIss(String iss) {
		this.iss = iss;
	}

	public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}

	public String getSub() {
		return sub;
	}

	public void setSub(String sub) {
		this.sub = sub;
	}

	public String getTyp() {
		return typ;
	}

	public void setTyp(String typ) {
		this.typ = typ;
	}

	public String getAzp() {
		return azp;
	}

	public void setAzp(String azp) {
		this.azp = azp;
	}

	public int getAuthTime() {
		return auth_time;
	}

	public void setAuthTime(int auth_time) {
		this.auth_time = auth_time;
	}

	public String getSessionState() {
		return session_state;
	}

	public void setSessionState(String session_state) {
		this.session_state = session_state;
	}

	public String getAcr() {
		return acr;
	}

	public void setAcr(String acr) {
		this.acr = acr;
	}

	public String getClientSession() {
		return client_session;
	}

	public void setClientSession(String client_session) {
		this.client_session = client_session;
	}

	public ArrayList<String> getAllowedOrigins() {
		return allowed_origins;
	}

	public void setAllowedOrigins(ArrayList<String> allowed_origins) {
		this.allowed_origins = allowed_origins;
	}

	public ArrayList<String> getRoles() {
		return roles;
	}

	public void setRoles(ArrayList<String> roles) {
		this.roles = roles;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getPreferredUsername() {
		return preferred_username;
	}

	public void setPreferredUsername(String preferred_username) {
		this.preferred_username = preferred_username;
	}

	public boolean isValid() {
		return isValid;
	}

	public void setValid(boolean isValid) {
		this.isValid = isValid;
	}

	public String getHeader() {
		return header;
	}

	public String getPayload() {
		return payload;
	}

	public String getSignature() {
		return signature;
	}

	public void setHeader(String header) {
		this.header = header;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public OAuthToken parseEncryptedJWT(String jwt, String secret, String clientId) {
		String token;
		try {
			token = Jiron.unseal(jwt, secret, Jiron.DEFAULT_ENCRYPTION_OPTIONS, Jiron.DEFAULT_INTEGRITY_OPTIONS);
			if (token != null) {
				JSONObject obj = new JSONObject(token);
				token = obj.getString("token");
			}
		} catch (JironException | JironIntegrityException e) {
			logger.error("Error while deciphering token " + e.getMessage());
			return null;
		}
		return parseDecryptedJWT(token, clientId);
	}

	public OAuthToken parseDecryptedJWT(String decryptedToken, String clientId) {
//		String[] cookie = decryptedToken.split("\\.");
//		String token = cookie[1];
		String token = decryptedToken;
		String[] jwtParts = token.split("\\.");
		if (jwtParts.length == 3) {
			String header = jwtParts[0];
			this.header = header;
			String payload = jwtParts[1];
			this.payload = payload;
			String RSASignature = jwtParts[2];
			this.signature = RSASignature;
			try {
				parseHeader(header);
				parsePayload(payload, clientId);
			} catch (UnsupportedEncodingException e) {
				logger.error("Error while base64 decoding the token " + e.getMessage());
				return null;
			}
		}
		return this;
	}

	private void parseHeader(String header) throws JSONException, UnsupportedEncodingException {
		logger.debug("BEGIN parsing OAuth token header");

		if (header == null)
			return;
		byte[] decodedBytes = Base64.getDecoder().decode(header);
		JSONObject obj = new JSONObject(new String(decodedBytes, "UTF-8"));
		this.setAlg(obj.getString("alg"));

		logger.debug("END parsing OAuth token payload");
	}

	private void parsePayload(String payload, String clientId) throws UnsupportedEncodingException {
		logger.debug("BEGIN parsing OAuth token payload");
		JSONObject obj = null;

		if (payload == null)
			return;
		byte[] decodedBytes = Base64.getDecoder().decode(payload);
		obj = new JSONObject(new String(decodedBytes, "UTF-8"));
		// *1000L because unix timestamp are in second
		// and java Date timestamps are in ms
		try {
			this.setExp(new Date(obj.getLong("exp") * 1000L));
			this.setAud(obj.getString("aud"));
			this.setAzp(obj.getString("azp"));
			JSONArray rolesJson = new JSONArray();
			rolesJson = obj.getJSONObject("resource_access").getJSONObject(clientId).getJSONArray("roles");
			ArrayList<String> rolesList = new ArrayList<String>();
			rolesJson.forEach(role -> {
				rolesList.add((String) role);
			});
			this.setRoles(rolesList);
			this.setJti(obj.getString("jti"));
			this.setNbf(obj.getInt("nbf"));
			this.setIat(new Date(obj.getLong("nbf") * 1000L));
			this.setIss(obj.getString("iss"));
			this.setSub(obj.getString("sub"));
			this.setTyp(obj.getString("typ"));
			this.setSessionState(obj.getString("session_state"));
			this.setClientSession(obj.getString("client_session"));
			this.setName(obj.getString("name"));
			this.setPreferredUsername(obj.getString("preferred_username"));
		} catch (JSONException ex) {
			logger.error("Error while parsing json OAuth Token " + ex.getLocalizedMessage());
		}
		logger.debug("END parsing OAuth token payload");
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{Token Id: " + this.jti + "}\n");
		sb.append("{Expiration date: " + this.exp.toString() + "}\n");
		sb.append("User roles: " + this.roles);
		sb.append("[");
		Strings.join(this.roles, ",");
		sb.append("]");
		return sb.toString();
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}
}
