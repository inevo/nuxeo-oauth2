package org.nuxeo.ecm.platform.oauth2.tokens;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.directory.Session;
import org.nuxeo.ecm.directory.api.DirectoryService;
import org.nuxeo.runtime.api.Framework;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.CredentialStore;

public class OAuth2TokenStore implements CredentialStore {

	protected static final Log log = LogFactory.getLog(OAuth2TokenStore.class);

    public static final String DIRECTORY_NAME = "oauth2Tokens";

	private String serviceName;
    
    public OAuth2TokenStore(String serviceName) {
    	this.serviceName = serviceName;
    }
    
	@Override
	public void store(String userId, Credential credential) {
		NuxeoOAuth2Token token = new NuxeoOAuth2Token(credential);
		token.setServiceName(serviceName);
		token.setNuxeoLogin(userId);
		try {
			storeTokenAsDirectoryEntry(token);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public void delete(String userId, Credential credential) {
		return;
	}

	@Override
	public boolean load(String userName, Credential credential) {
		try {
			
			NuxeoOAuth2Token token = getToken(serviceName, userName);

			credential.setAccessToken(token.getAccessToken());
			credential.setRefreshToken(token.getRefreshToken());
			credential.setExpirationTimeMilliseconds(token.getExpirationTimeMilliseconds());
			return true;
		} catch (Exception e) {

			return false;
		}
	}

	public NuxeoOAuth2Token getToken(String serviceName, String nuxeoLogin)
            throws Exception {
        DirectoryService ds = Framework.getService(DirectoryService.class);
        Session session = null;
        try {
            session = ds.open(DIRECTORY_NAME);
            Map<String, Serializable> filter = new HashMap<String, Serializable>();
            filter.put("serviceName", serviceName);
            filter.put("nuxeoLogin", nuxeoLogin);
            DocumentModelList entries = session.query(filter);
            if (entries.size() == 0) {
                return null;
            }
            if (entries.size() > 1) {
                log.error("Found several tokens");
            }
            return getTokenFromDirectoryEntry(entries.get(0));
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }
	
	protected NuxeoOAuth2Token getTokenFromDirectoryEntry(DocumentModel entry)
			throws ClientException {
		return new NuxeoOAuth2Token(entry);
	}

	
	protected NuxeoOAuth2Token storeTokenAsDirectoryEntry(
            NuxeoOAuth2Token aToken) throws Exception {
        DirectoryService ds = Framework.getService(DirectoryService.class);
        Session session = null;
        try {
            session = ds.open(DIRECTORY_NAME);
            DocumentModel entry = session.createEntry(aToken.toMap());
            session.updateEntry(entry);

            return getToken(serviceName, aToken.getNuxeoLogin());
        } finally {
            if (session != null) {
                session.close();
            }
        }
    }

}