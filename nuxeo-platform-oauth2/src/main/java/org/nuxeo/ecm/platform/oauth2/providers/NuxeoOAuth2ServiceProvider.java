package org.nuxeo.ecm.platform.oauth2.providers;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.platform.oauth2.tokens.OAuth2TokenStore;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.CredentialStore;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;

public class NuxeoOAuth2ServiceProvider {

	public static final String SCHEMA = "oauth2ServiceProvider";

	protected String serviceName;

	protected Long id;

	private String tokenServerURL;

	private String authorizationServerURL;

	private String clientId;

	private String clientSecret;

	private List<String> scopes;

	public NuxeoOAuth2ServiceProvider(Long id, String serviceName, String authorizationServerURL, String tokenServerURL, 
			String clientId, String clientSecret, List<String> scopes) {
		this.id = id;
		this.serviceName = serviceName;
		this.tokenServerURL = tokenServerURL;
		this.authorizationServerURL = authorizationServerURL;
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.scopes = scopes;
	}



	public static NuxeoOAuth2ServiceProvider createFromDirectoryEntry(DocumentModel entry) throws ClientException {

		String authorizationServerURL = (String) entry.getProperty(SCHEMA, "authorizationServerURL");
		String tokenServerURL = (String) entry.getProperty(SCHEMA, "tokenServerURL");
		Long id = (Long) entry.getProperty(SCHEMA, "id");
		String serviceName = (String) entry.getProperty(SCHEMA, "serviceName");
		String clientId = (String) entry.getProperty(SCHEMA, "clientId");
		String clientSecret = (String) entry.getProperty(SCHEMA, "clientSecret");
		String scopes = (String) entry.getProperty(SCHEMA, "scopes");

		return new NuxeoOAuth2ServiceProvider(id, serviceName, authorizationServerURL, tokenServerURL, clientId, clientSecret, (List<String>) Arrays.asList(scopes.split(",")));

	}

	protected DocumentModel asDocumentModel(DocumentModel entry) throws ClientException {

		entry.setProperty(SCHEMA, "serviceName", serviceName);
		entry.setProperty(SCHEMA, "authorizationServerURL", authorizationServerURL);
		entry.setProperty(SCHEMA, "tokenServerURL", tokenServerURL);
		entry.setProperty(SCHEMA, "clientId", clientId);
		entry.setProperty(SCHEMA, "clientSecret", clientSecret);
		entry.setProperty(SCHEMA, "scopes", StringUtils.join(scopes, ","));

		return entry;
	}

	public AuthorizationCodeFlow getAuthorizationCodeFlow( HttpTransport transport, JsonFactory jsonFactory) {
		
		Credential.AccessMethod method = BearerToken.authorizationHeaderAccessMethod();
		GenericUrl tokenServerUrl = new GenericUrl(tokenServerURL);
		HttpExecuteInterceptor clientAuthentication = new ClientParametersAuthentication(clientId, clientSecret);
		String authorizationServerUrl = authorizationServerURL;
		
		AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
				method, transport, jsonFactory,
				tokenServerUrl, clientAuthentication, 
				clientId, authorizationServerUrl)
		.setScopes(scopes)
		.setCredentialStore(getCredentialStore())
		.build();

		return flow;
	}

	public CredentialStore getCredentialStore() {
		return new OAuth2TokenStore(serviceName);
	}
	public String getServiceName() {
		return serviceName;
	}

	public Long getId() {
		return id;
	}


}

