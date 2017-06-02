package org.elasticsearch.plugin.readonlyrest.rules;

import static org.mockito.Mockito.when;

import java.util.Calendar;

import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.readonlyrest.ConfigurationHelper;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleExitResult;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleNotConfiguredException;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.SyncRule;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.impl.TokenSyncRule;
import org.elasticsearch.plugin.readonlyrest.oauth.OAuthToken;
import org.elasticsearch.plugin.readonlyrest.wiring.requestcontext.RequestContext;
import org.junit.Test;
import org.mockito.Mockito;

import junit.framework.TestCase;

public class TokenSyncRuleTests extends TestCase {
	private ConfigurationHelper conf;
	private final String cookieName = "datasweet-oauth";
	private final String cookieSecret = "3eeadfea0896c1a51b41d09aa1eab3d6c24d2154";
	private final String tokenClientId = "demo";
	private final String tokenSecret = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkBpwYFlAqMcQhdbSOkkOHu3cU39EioKzWdmmkD8HZS0vfuiqij/PgqMJvF49EXwiclCLgGmf71pvZxazEHp2sqQmkUYeF9xAUPvRKurNE2krd69g+nGiOCvoNMZ10APeO3FU36EOtn2cxoYXUs/qkNBQZf1YZaI0BfWqjhwI9ndFwbx2D8o4YliGfJdagDJhueJ4X3L++pqfk7f8UYXehmE9T+2ymJPbSkx7Lw9YQFIoRYdWzAfFJebk1v0FUE1mmfTSDEye47UvYxec4StYzo1f1K3SgXwUTl1EuhClH1eX+XAuQYHWczR9sXH3kGAvKFsJ/azVBh0N1M1hs+N97wIDAQAB";
	
	protected void setUp() throws Exception {
		super.setUp();
		conf = Mockito.mock(ConfigurationHelper.class);
		conf.cookieName = cookieName;
		conf.cookieSecret = cookieSecret;
		conf.tokenClientId = tokenClientId;
		conf.tokenSecret = tokenSecret;
	}
	
	private RuleExitResult match(String configured, RequestContext rc) throws RuleNotConfiguredException {
		SyncRule r = new TokenSyncRule(Settings.builder().put("auth_oauth", configured).build(), conf);
		return r.match(rc);
	}
	
	@Test
	public void testExpiredandWrongAlgo() throws RuleNotConfiguredException {
		OAuthToken emptyExpiredToken = new OAuthToken();
		Calendar c = Calendar.getInstance();
		c.set(Calendar.HOUR_OF_DAY, c.get(Calendar.HOUR_OF_DAY) -1);
		emptyExpiredToken.setExp(c.getTime());
		emptyExpiredToken.setAlg("test");
		
		RequestContext rc = Mockito.mock(RequestContext.class);
		when(rc.getToken()).thenReturn(emptyExpiredToken);
		RuleExitResult res = match("true", rc);
		assertFalse(res.isMatch());
	}
	
	@Test
	public void testValidTokenButWrongAlgo() throws RuleNotConfiguredException {
		OAuthToken emptyValidToken = new OAuthToken();
		Calendar c = Calendar.getInstance();
		c.set(Calendar.HOUR_OF_DAY, c.get(Calendar.HOUR_OF_DAY) + 2);
		emptyValidToken.setExp(c.getTime());
		emptyValidToken.setAlg("test");
		
		RequestContext rc = Mockito.mock(RequestContext.class);
		when(rc.getToken()).thenReturn(emptyValidToken);
		RuleExitResult res = match("true", rc);
		assertFalse(res.isMatch());
	}
	
	@Test
	public void testTokenIntegrity() throws RuleNotConfiguredException {
		OAuthToken validToken = new OAuthToken();
		Calendar c = Calendar.getInstance();
		c.set(Calendar.HOUR_OF_DAY, c.get(Calendar.HOUR_OF_DAY) + 2);
		validToken.setExp(c.getTime());
		validToken.setAlg("RS256");
		validToken.setHeader("eyJhbGciOiJSUzI1NiJ9");
		validToken.setPayload("eyJqdGkiOiJiYThiMmMyNC0wYjZmLTRmODItYTljNi00OTBhYzhlYTQyN2EiLCJleHAiOjE0OTQ4NjE1NDcsIm5iZiI6MCwiaWF0IjoxNDk0ODYwMzQ3LCJpc3MiOiJodHRwczovL2RlbW8uYWx0YW5vdmEuZnIvYXV0aC9yZWFsbXMvRGF0YVN3ZWV0IiwiYXVkIjoiZGVtbyIsInN1YiI6IjdjNDIzM2U3LTI3YzMtNDk2Mi04M2FhLTBjMjkxNzRjNmJjMCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRlbW8iLCJzZXNzaW9uX3N0YXRlIjoiYzI4Yjc0OGItMWY2NC00ZjI2LTg0NzgtODY3MWEzY2RkMWZkIiwiY2xpZW50X3Nlc3Npb24iOiI0YmJmMzU0Yi00ZjdhLTQzNjktODdhMi01YmM2NGVkMWUyOTkiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9yZWMtdGhvbWFzY29vay5kYXRhc3dlZXQuZnIvIiwiaHR0cDovL2xvY2FsaG9zdDo5MDkwIiwiaHR0cHM6Ly9kZW1vLmFsdGFub3ZhLmZyIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NTYwMSJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJkZW1vIjp7InJvbGVzIjpbIlZpZXdlciIsIkFkbWluIiwiRWRpdG9yIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50Iiwidmlldy1wcm9maWxlIl19fSwibmFtZSI6IlJvbWFpbiBWaWJyYWMiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJydmlicmFjIiwiZ2l2ZW5fbmFtZSI6IlJvbWFpbiIsImZhbWlseV9uYW1lIjoiVmlicmFjIiwiZW1haWwiOiJyb21haW4udmlicmFjQGFsdGFub3ZhLmZyIn0");
		validToken.setSignature(".dFkTvE9n4QMlKF0D5JyAF353VYLRfpYQXY9pQqoAFGlQgnyeC9RnTLxCWyLwlgl4S8_6EvKRgDc2TEieDs40h7k6oxDP_b5biYAj95IBvO9Ij72q0vsyATaRwvvx1VkPhhLoxx4gLyxh8fWSt6QoNNP1PQ1VvGKGZ-ehQTXzg_2GM29exQtHisQpM6PgR_I39IGz4uk3OLmLJYmPlLfpLPu2MkhnKW9UCL5MaP0EMMeomhTLa689lR8WPtEJ99ixxGptVD-6EtXBxOSoFrUi317KaCACJgxcrMBWEEkVoS5NMr8D_m-4A3G7_neSicRq4z9Q_48gyD9UUzT6VUfxlg");
		validToken.setPublicKey(tokenSecret);
		
		RequestContext rc = Mockito.mock(RequestContext.class);
		when(rc.getToken()).thenReturn(validToken);
		RuleExitResult res = match("true", rc);
		assertTrue(res.isMatch());
	}
	
	@Test
	public void testTokenExpDateKO() throws RuleNotConfiguredException {
		OAuthToken expiredToken = new OAuthToken();
		Calendar c = Calendar.getInstance();
		c.set(Calendar.HOUR_OF_DAY, c.get(Calendar.HOUR_OF_DAY) -1);
		expiredToken.setExp(c.getTime());
		expiredToken.setAlg("RS256");
		expiredToken.setHeader("eyJhbGciOiJSUzI1NiJ9");
		expiredToken.setPayload("eyJqdGkiOiJiYThiMmMyNC0wYjZmLTRmODItYTljNi00OTBhYzhlYTQyN2EiLCJleHAiOjE0OTQ4NjE1NDcsIm5iZiI6MCwiaWF0IjoxNDk0ODYwMzQ3LCJpc3MiOiJodHRwczovL2RlbW8uYWx0YW5vdmEuZnIvYXV0aC9yZWFsbXMvRGF0YVN3ZWV0IiwiYXVkIjoiZGVtbyIsInN1YiI6IjdjNDIzM2U3LTI3YzMtNDk2Mi04M2FhLTBjMjkxNzRjNmJjMCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImRlbW8iLCJzZXNzaW9uX3N0YXRlIjoiYzI4Yjc0OGItMWY2NC00ZjI2LTg0NzgtODY3MWEzY2RkMWZkIiwiY2xpZW50X3Nlc3Npb24iOiI0YmJmMzU0Yi00ZjdhLTQzNjktODdhMi01YmM2NGVkMWUyOTkiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cHM6Ly9yZWMtdGhvbWFzY29vay5kYXRhc3dlZXQuZnIvIiwiaHR0cDovL2xvY2FsaG9zdDo5MDkwIiwiaHR0cHM6Ly9kZW1vLmFsdGFub3ZhLmZyIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NTYwMSJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJkZW1vIjp7InJvbGVzIjpbIlZpZXdlciIsIkFkbWluIiwiRWRpdG9yIl19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50Iiwidmlldy1wcm9maWxlIl19fSwibmFtZSI6IlJvbWFpbiBWaWJyYWMiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJydmlicmFjIiwiZ2l2ZW5fbmFtZSI6IlJvbWFpbiIsImZhbWlseV9uYW1lIjoiVmlicmFjIiwiZW1haWwiOiJyb21haW4udmlicmFjQGFsdGFub3ZhLmZyIn0");
		expiredToken.setSignature(".dFkTvE9n4QMlKF0D5JyAF353VYLRfpYQXY9pQqoAFGlQgnyeC9RnTLxCWyLwlgl4S8_6EvKRgDc2TEieDs40h7k6oxDP_b5biYAj95IBvO9Ij72q0vsyATaRwvvx1VkPhhLoxx4gLyxh8fWSt6QoNNP1PQ1VvGKGZ-ehQTXzg_2GM29exQtHisQpM6PgR_I39IGz4uk3OLmLJYmPlLfpLPu2MkhnKW9UCL5MaP0EMMeomhTLa689lR8WPtEJ99ixxGptVD-6EtXBxOSoFrUi317KaCACJgxcrMBWEEkVoS5NMr8D_m-4A3G7_neSicRq4z9Q_48gyD9UUzT6VUfxlg");
		expiredToken.setPublicKey(tokenSecret);
		
		RequestContext rc = Mockito.mock(RequestContext.class);
		when(rc.getToken()).thenReturn(expiredToken);
		RuleExitResult res = match("true", rc);
		assertFalse(res.isMatch());
	}
	
	@Test
	public void testNullToken() throws RuleNotConfiguredException {
		RequestContext rc = Mockito.mock(RequestContext.class);
		when(rc.getToken()).thenReturn(null);
		RuleExitResult res = match("true", rc);
		assertFalse(res.isMatch());
	}
	
	@Test
	public void testThrowRuleNotConfiguredException() {
		RequestContext rc = Mockito.mock(RequestContext.class);
		try {
			match("", rc);
		} catch (RuleNotConfiguredException e) {
			assertTrue(true);
		}
		assertFalse(false);
	}

}
