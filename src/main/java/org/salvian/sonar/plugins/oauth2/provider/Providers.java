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

import org.apache.oltu.oauth2.common.OAuthProviderType;

public enum Providers {

    FACEBOOK(new GenericProvider(OAuthProviderType.FACEBOOK)),
    FOURSQUARE(new GenericProvider(OAuthProviderType.FOURSQUARE)),
    GITHUB(new GenericProvider(OAuthProviderType.GITHUB)),
    GOOGLE(new GoogleProvider()),
    INSTAGRAM(new GenericProvider(OAuthProviderType.INSTAGRAM)),
    LINKEDIN(new GenericProvider(OAuthProviderType.LINKEDIN)),
    MICROSOFT(new GenericProvider(OAuthProviderType.MICROSOFT)),
    PAYPAL(new GenericProvider(OAuthProviderType.PAYPAL)),
    REDDIT(new GenericProvider(OAuthProviderType.REDDIT)),
    SALESFORCE(new GenericProvider(OAuthProviderType.SALESFORCE)),
    YAMMER(new GenericProvider(OAuthProviderType.YAMMER));

    private final OAuth2Provider provider;

    Providers(OAuth2Provider provider) {

        this.provider = provider;
    }

    public OAuth2Provider get() {
        return this.provider;
    }

}
