package org.nuxeo.ecm.platform.oauth2.providers;

import java.util.List;

public interface OAuth2ServiceProviderRegistry {
	NuxeoOAuth2ServiceProvider getProvider(String serviceName);
	NuxeoOAuth2ServiceProvider addProvider(String serviceName, String tokenServerURL, 
			String authorizationServerURL, String clientId, String clientSecret, List<String> scopes) throws Exception;
}
