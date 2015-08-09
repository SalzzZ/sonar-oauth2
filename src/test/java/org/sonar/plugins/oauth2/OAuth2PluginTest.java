/*
 * Copyright 2015, Joseph "Deven" Phillips
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
package org.sonar.plugins.oauth2;

import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;

import static org.fest.assertions.Assertions.*;

/**
 * Unit tests for the OAuth2Plugin class
 *
 * @author <a href="https://github.com/InfoSec812">Deven Phillips</a>
 * @author <a href="https://github.com/alexlew">Alexandre Lewandowski</a>
 */
public class OAuth2PluginTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testGetExtensions() {
    System.out.println("getExtensions");
    OAuth2Plugin instance = new OAuth2Plugin();
    List result = instance.getExtensions();
    assertThat(result).isNotNull().as("getExtensions MUST NOT return a NULL object.");
    assertThat(result).isNotEmpty().as("getExtensions MUST NOT return an empty list.");
    assertThat(result).containsExactly(OAuth2Plugin.Extensions.class);
  }

  @Test
  public void enable_extensions_if_OAuth2_realm_is_enabled() {
    Settings settings = new Settings()
            .setProperty("sonar.security.realm", "OAuth2")
            .setProperty("sonar.authenticator.createUsers", "true");
    List<ServerExtension> extensions = (List<ServerExtension>) new OAuth2Plugin.Extensions(settings).provide();

    assertThat(extensions).hasSize(7);
    assertThat(extensions).doesNotHaveDuplicates();
    assertThat(extensions).contains(OAuth2AuthenticationFilter.class);
  }

  @Test
  public void when_OAuth2_is_enabled_then_property_createUsers_must_be_true() {
    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("Property sonar.authenticator.createUsers must be set to true");

    Settings settings = new Settings()
            .setProperty("sonar.security.realm", "OAuth2")
            .setProperty("sonar.authenticator.createUsers", "false");

    new OAuth2Plugin.Extensions(settings).provide();
  }

  @Test
  public void when_realm_is_default_then_extension_should_be_disabled() {
    Settings settings = new Settings();
    List<ServerExtension> extensions = (List<ServerExtension>) new OAuth2Plugin.Extensions(settings).provide();

    assertThat(extensions).isEmpty();
  }

  @Test
  public void when_OAuth2_realm_is_disabled_then_disable_extensions() {
    Settings settings = new Settings().setProperty("sonar.security.realm", "Other");
    List<ServerExtension> extensions = (List<ServerExtension>) new OAuth2Plugin.Extensions(settings).provide();

    assertThat(extensions).isEmpty();
  }
}