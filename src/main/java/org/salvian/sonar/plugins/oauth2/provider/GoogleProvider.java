/*
 * Copyright 2015, Alexandre Lewandowski
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.salvian.sonar.plugins.oauth2.provider;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.OAuthProviderType;
import org.salvian.sonar.plugins.oauth2.GenericProfile;
import org.salvian.sonar.plugins.oauth2.OAuth2Client;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;

import java.util.Collections;

public class GoogleProvider extends GenericProvider {
    private static final Logger LOG = LoggerFactory.getLogger(GoogleProvider.class);
    public static final String PROPERTY_GOOGLE_HD = "sonar.oauth2.google.hd";

    private static final String SCOPE = "openid profile email";

    public GoogleProvider() {
        super(OAuthProviderType.GOOGLE);
    }

    @Override
    public OAuthClientRequest.AuthenticationRequestBuilder createRedirectRequestBuilder(Settings settings) {
        OAuthClientRequest.AuthenticationRequestBuilder redirectRequestBuilder;
        redirectRequestBuilder = super.createRedirectRequestBuilder(settings);
        redirectRequestBuilder.setParameter("response_type", "code");
        redirectRequestBuilder.setParameter("scope", SCOPE);
        redirectRequestBuilder.setParameter("access_type", "offline");
        if (settings.hasKey(PROPERTY_GOOGLE_HD))
            redirectRequestBuilder.setParameter("hd", settings.getString(PROPERTY_GOOGLE_HD));
        return redirectRequestBuilder;
    }

    @Override
    public GenericProfile validateTokenAndGetUser(Settings settings, OAuthJSONAccessTokenResponse tokenResponse) {
        try {
            //TODO: use general method to validate Oauth2 token (instead of using 1 library per provider)
            HttpTransport transport = GoogleNetHttpTransport.newTrustedTransport();
            JsonFactory jsonFactory = JacksonFactory.getDefaultInstance();
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                    .setAudience(Collections.singletonList(settings.getString(OAuth2Client.PROPERTY_CLIENT_ID)))
                    .build();
            GoogleIdToken googleToken = verifier.verify(tokenResponse.getParam("id_token"));
            if (googleToken != null) {
                GoogleIdToken.Payload payload = googleToken.getPayload();
                if (!payload.getHostedDomain().equals(PROPERTY_GOOGLE_HD)) {
                    LOG.error("Use your " + PROPERTY_GOOGLE_HD + " google account to log in");
                }
                GenericProfile googleProfile = new GenericProfile();
                String email = payload.getEmail();
                googleProfile.setEmail(email);
                googleProfile.setName(email.substring(0, email.indexOf("@")));
                return googleProfile;
            } else {
                LOG.error("Nice try, but.. nope");
            }
        } catch (Exception e) {
            LOG.error("You are not logged in");
        }
        return null;
    }

}
