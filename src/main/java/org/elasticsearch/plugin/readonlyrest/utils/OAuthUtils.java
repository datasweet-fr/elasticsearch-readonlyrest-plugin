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

package org.elasticsearch.plugin.readonlyrest.utils;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.elasticsearch.plugin.readonlyrest.ConfigurationHelper;
import org.elasticsearch.plugin.readonlyrest.oauth.OAuthToken;

import com.google.common.base.Strings;

public class OAuthUtils {
	
	/**
	 * Extract token from Bearer Authorization header
	 * @param authorizationHeader
	 * 		the header
	 * @return
	 * 		the token extracted
	 */
    public static String extractTokenFromHeader(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.trim().length() == 0 || !authorizationHeader.contains("Bearer "))
            return null;
        String interestingPart = authorizationHeader.split("Bearer")[1].trim();
        if (interestingPart.length() == 0) {
            return null;
        }
        return interestingPart;
    }
    
    /**
     * Extract token from Cookie
     * @param cookieHeader
     * 		the cookie
     * @param cookieName
     * 		the name of the cookie
     * @return
     * 		the token extracted
     */
    public static String extractTokenFromCookie(String cookieHeader, String cookieName) {
        String token = cookieHeader;
        if (token == null || token.trim().length() == 0 || !token.contains(cookieName))
            return null;
        String interestingPart = token.substring(token.indexOf(cookieName));
        interestingPart = interestingPart.substring(interestingPart.indexOf("=") + 1);
        return interestingPart;
    }

    public static OAuthToken getOAuthToken(Map<String, String> headers, String cookieName, String cookieSecret, String tokenClientId, String tokenSecret) {
    	if (headers == null)
    		return null;
        String tokenCookie = extractTokenFromCookie(headers.get("Cookie"), cookieName);
        String tokenHeader = extractTokenFromHeader(headers.get("Authorization"));
        OAuthToken oAuthToken = new OAuthToken();
        oAuthToken.setPublicKey(tokenSecret);
        if (!Strings.isNullOrEmpty(tokenCookie)) {
            return oAuthToken.parseEncryptedJWT(tokenCookie, cookieSecret, tokenClientId);
        }
        else if (!Strings.isNullOrEmpty(tokenHeader)) {
            try {
                return oAuthToken.parseDecryptedJWT(tokenHeader, tokenClientId);
            } catch (IllegalArgumentException e) {
                e.printStackTrace();
            }
        }
        return null;
    }
    
    public static boolean verifyTokenIntegrity(OAuthToken token, String tokenPublicKey) {
    	if (token == null || tokenPublicKey == null)
    		return false;
    	String header = token.getHeader();
    	String payload = token.getPayload();
    	String signature = token.getSignature();
    	String algo = token.getAlg();
    	if ("RS256".equals(algo)) {
    		byte[] decoded = Base64.decodeBase64(tokenPublicKey);
    		X509EncodedKeySpec spec =
    	            new X509EncodedKeySpec(decoded);
    	    KeyFactory kf;
    	    try {
    	    	kf = KeyFactory.getInstance("RSA");
    			RSAPublicKey generatePublic = (RSAPublicKey) kf.generatePublic(spec);
    			byte[] contentBytes = String.format("%s.%s", header, payload).getBytes(StandardCharsets.UTF_8);
    		    byte[] signatureBytes = Base64.decodeBase64(signature);
    		    Signature s = Signature.getInstance("SHA256withRSA");
    		    s.initVerify(generatePublic);
    		    s.update(contentBytes);
    		    s.verify(signatureBytes);
    		    return true;
    	    } catch (Exception e) {
    	    	e.printStackTrace();
    	    	return false;
    	    }
    	} else if ("HS256".equals(algo)) {
    		// TODO
    	} // and so on
    		
    	return false;
    }
}


