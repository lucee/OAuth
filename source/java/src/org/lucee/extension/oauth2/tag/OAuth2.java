/**
 *
 * Copyright (c) 2015, Lucee Assosication Switzerland
 * Copyright (c) 2014, the Railo Company Ltd. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either 
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public 
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 * 
 **/
package org.lucee.extension.oauth2.tag;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest.AuthenticationRequestBuilder;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest.TokenRequestBuilder;
import org.apache.oltu.oauth2.client.response.GitHubTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.OAuthProviderType;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.lucee.extension.oauth2.util.Functions;

import lucee.loader.engine.CFMLEngineFactory;
import lucee.loader.util.Util;
import lucee.runtime.exp.PageException;
import lucee.runtime.type.Collection;
import lucee.runtime.type.Collection.Key;
import lucee.runtime.type.Struct;
import lucee.runtime.util.Creation;

/**
 * Required for cfhttp POST operations, cfhttpparam is used to specify the
 * parameters necessary to build a cfhttp POST.
 *
 *
 *
 **/
public final class OAuth2 extends TagImpl {

	private static final Map<String, ProviderData> PROVIDERS = new ConcurrentHashMap<>();

	static {
		PROVIDERS.put("FACEBOOK", new ProviderData(OAuthProviderType.FACEBOOK, "https://graph.facebook.com/me"));
		PROVIDERS.put("FOURSQUARE", new ProviderData(OAuthProviderType.FOURSQUARE));
		PROVIDERS.put("GITHUB", new ProviderData(OAuthProviderType.GITHUB, "https://api.github.com/user"));
		PROVIDERS.put("GOOGLE",
				new ProviderData(OAuthProviderType.GOOGLE, "https://www.googleapis.com/oauth2/v1/userinfo")
						.addDefaultScope("https://www.googleapis.com/auth/userinfo.profile")
						.addScope("profile", "https://www.googleapis.com/auth/userinfo.profile")
						.addScope("email", "https://www.googleapis.com/auth/userinfo.email"));
		PROVIDERS.put("INSTAGRAM", new ProviderData(OAuthProviderType.INSTAGRAM));
		PROVIDERS.put("LINKEDIN", new ProviderData(OAuthProviderType.LINKEDIN));
		PROVIDERS.put("MICROSOFT", new ProviderData(OAuthProviderType.MICROSOFT));
		PROVIDERS.put("PAYPAL", new ProviderData(OAuthProviderType.PAYPAL));
		PROVIDERS.put("REDDIT", new ProviderData(OAuthProviderType.REDDIT));
		PROVIDERS.put("SALESFORCE", new ProviderData(OAuthProviderType.SALESFORCE));
		PROVIDERS.put("YAMMER", new ProviderData(OAuthProviderType.YAMMER));

	}

	private ProviderData provider;
	private String clientid;
	private String scope;
	private String state;
	private String authendpoint;
	private String secretkey;
	private String accesstokenendpoint;
	private String result = "cfoauth";
	private URL redirecturi;

	private String urlparams;
	private static final Collection.Key CODE;
	private static final Collection.Key NAME;
	private static final Collection.Key LOCALE;
	private static final Collection.Key GENDER;
	private static final Collection.Key ID;
	private static final Collection.Key OTHER;
	private static final Collection.Key ACCESS_TOKEN;
	private static final Collection.Key REFRESH_TOKEN;
	private static final Collection.Key EXPIRES_IN;
	private static final Collection.Key RESPONSE_CODE;

	static {
		Creation cast = CFMLEngineFactory.getInstance().getCreationUtil();
		CODE = cast.createKey("code");
		NAME = cast.createKey("name");
		LOCALE = cast.createKey("locale");
		GENDER = cast.createKey("gender");
		ID = cast.createKey("id");
		OTHER = cast.createKey("other");
		ACCESS_TOKEN = cast.createKey("access_token");
		REFRESH_TOKEN = cast.createKey("refresh_token");
		EXPIRES_IN = cast.createKey("expires_in");
		RESPONSE_CODE = cast.createKey("response_code");
	}

	@Override
	public void release() {
		accesstokenendpoint = null;
		authendpoint = null;
		redirecturi = null;
		result = "cfoauth";
		secretkey = null;
		clientid = null;
		scope = null;
		state = null;
		provider = null;
	}

	public void setAccesstokenendpoint(String accesstokenendpoint) {
		this.accesstokenendpoint = accesstokenendpoint;
	}

	public void setAuthendpoint(String authendpoint) {
		this.authendpoint = authendpoint;
	}

	public void setRedirecturi(String redirecturi) throws MalformedURLException {
		this.redirecturi = engine.getHTTPUtil().toURL(redirecturi);
	}

	public void setResult(String result) {
		this.result = result;
	}

	public void setClientid(String clientid) {
		this.clientid = clientid;
	}

	public void setScope(String scope) {
		if (Util.isEmpty(scope, true))
			return;
		this.scope = scope;

	}

	public void setState(String state) {
		if (Util.isEmpty(state, true))
			return;
		this.state = state;
	}

	public void setSecretkey(String secretkey) {
		this.secretkey = secretkey;
	}

	public void setType(String type) {
		if (Util.isEmpty(type))
			return;
		type = type.trim();
		// TODO DISTROKID
		provider = PROVIDERS.get(type.toUpperCase());

		if (provider == null)
			engine.getExceptionUtil().createApplicationException(
					"[" + type + "] is not supported as attribute for the attribute [type] from tag [oauth]",
					"valid values are [" + engine.getListUtil()
							.toList(PROVIDERS.keySet().toArray(new String[PROVIDERS.size()]), ", ") + "]");
	}

	public void setUrlparams(String urlparams) {
		this.urlparams = urlparams;
	}

	@Override
	public int doStartTag() throws PageException {
		String code = engine.getCastUtil().toString(pageContext.urlScope().get(CODE, null), null);

		if (Util.isEmpty(code, true)) {
			handleCodeRequest();
		} else {
			handleTokenRequest(code);
		}
		return SKIP_BODY;
	}

	private void handleCodeRequest() throws PageException {

		String scope = provider.getScope(this.scope);

		try {
			AuthenticationRequestBuilder builder = OAuthClientRequest.authorizationProvider(provider.type)
					.setClientId(clientid).setRedirectURI(redirecturi.toExternalForm()).setResponseType("code");

			if (scope != null)
				builder.setScope(scope == null ? "" : scope);
			if (state != null)
				builder.setState(state);
			OAuthClientRequest request = builder.buildQueryMessage();
			// TODO do a more Lucee approcah?
			pageContext.getHttpServletResponse().sendRedirect(request.getLocationUri());

		} catch (Exception e) {
			throw engine.getCastUtil().toPageException(e);
		}
	}

	private void handleTokenRequest(String code) throws PageException {

		OAuthAuthzResponse oar;
		try {
			oar = OAuthAuthzResponse.oauthCodeAuthzResponse(pageContext.getHttpServletRequest());
		} catch (OAuthProblemException e) {
			throw engine.getCastUtil().toPageException(e);
		}

		try {
			TokenRequestBuilder builder = OAuthClientRequest.tokenProvider(provider.type)
					.setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(clientid)
					.setRedirectURI(redirecturi.toExternalForm()).setCode(oar.getCode());
			if (!Util.isEmpty(secretkey))
				builder.setClientSecret(secretkey);

			OAuthClientRequest req = builder.buildBodyMessage();
			OAuthClient client = new OAuthClient(new URLConnectionClient());

			System.err.println(req.getLocationUri());
			// Facebook is not fully compatible with OAuth 2.0 draft 10, access token
			// response is
			// application/x-www-form-urlencoded, not json encoded so we use dedicated
			// response class for that
			// Custom response classes are an easy way to deal with oauth providers that
			// introduce modifications to
			// OAuth 2.0 specification
			OAuthAccessTokenResponse rsp;
			if (OAuthProviderType.GITHUB == provider.type) {
				rsp = client.accessToken(req, OAuth.HttpMethod.POST, GitHubTokenResponse.class);
			} else {
				rsp = client.accessToken(req, OAuth.HttpMethod.POST);
			}

			Struct data = handleDataRequest(rsp.getAccessToken());

			Struct sct = engine.getCreationUtil().createStruct();

			rem(sct, data, NAME);
			rem(sct, data, LOCALE);
			rem(sct, data, GENDER);
			rem(sct, data, ID);
			sct.set(OTHER, data);
			sct.set(ACCESS_TOKEN, rsp.getAccessToken());
			sct.set(REFRESH_TOKEN, rsp.getRefreshToken());
			sct.set(EXPIRES_IN, rsp.getExpiresIn());
			sct.set(RESPONSE_CODE, rsp.getResponseCode());

			pageContext.setVariable(result, sct);

		} catch (Exception e) {
			throw engine.getCastUtil().toPageException(e);
		}
	}

	private static void rem(Struct sct, Struct data, Key key) {
		Object val = data.remove(key, null);
		if (val != null) {
			sct.setEL(key, val);
		}
	}

	private Struct handleDataRequest(String accessToken) throws PageException {
		OAuthResourceResponse resourceResponse;
		try {
			OAuthClientRequest resourceRequest = new OAuthBearerClientRequest(provider.getDefaultEndPoint())
					.setAccessToken(accessToken).buildHeaderMessage();

			OAuthClient client = new OAuthClient(new URLConnectionClient());
			resourceResponse = client.resource(resourceRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);
		} catch (Exception e) {
			throw engine.getCastUtil().toPageException(e);
		}

		String raw = resourceResponse.getBody();
		System.err.println(raw);

		return engine.getCastUtil().toStruct(Functions.evaluate(pageContext, raw));

	}

	@Override
	public int doEndTag() throws PageException {
		return EVAL_PAGE;
	}

	private static class ProviderData {
		private OAuthProviderType type;
		private String defaultScope;
		private String end;
		private Map<String, String> scopes = new HashMap<String, String>();

		public ProviderData(OAuthProviderType type) {
			this.type = type;
		}

		public ProviderData(OAuthProviderType type, String end) {
			this.type = type;
			this.end = end;
		}

		public String getScope(String custom) {
			if (custom == null)
				return defaultScope;

			// replace placeholder
			String tmp = scopes.get(custom.toLowerCase().trim());
			if (tmp != null)
				custom = tmp;

			// GOOGLE
			if (OAuthProviderType.GOOGLE == type && !custom.toLowerCase().contains(defaultScope)) {
				return defaultScope + " " + custom;
			}
			return custom;
		}

		public ProviderData addDefaultScope(String defaultScope) {
			this.defaultScope = defaultScope;
			return this;
		}

		public ProviderData addScope(String name, String scope) {
			scopes.put(name.toLowerCase().trim(), scope);
			return this;
		}

		public String getDefaultEndPoint() {
			return end;
		}

	}
}