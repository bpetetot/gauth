/*
 * Copyright 2014 Google Inc. All Rights Reserved.
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

package fr.mhz.bookie.services;

import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import fr.mhz.bookie.auth.Authenticate;
import fr.mhz.bookie.dao.UserDAO;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;

/**
 * The Haiku+ sample application is a simple database of user-submitted haikus. It allows for a
 * restricted set of functionality which would not be sufficient for a production application,
 * but is sufficient to demonstrate Google+ platform features, such as Google+ Sign-In,
 * personalization, app activities, over-the-air install, and interactive posts.
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class Services {

    /**
     * MIME type to use when sending responses back to clients.
     */
    public static final String JSON_MIMETYPE = "application/json";

    /**
     * JsonFactory to use in parsing JSON.
     */
    public static final JsonFactory JSON_FACTORY = new GsonFactory();

    /**
     * HttpTransport to use for external requests.
     */
    public static final HttpTransport TRANSPORT = new NetHttpTransport();

    public static final UserDAO userDao = new UserDAO();

    /**
     * Client secret configuration.  This is read from the client_secrets.json file.
     */
    private static GoogleClientSecrets clientSecrets;

    /**
     * This is the Client ID that you generated in the API Console.  It is stored
     * in the client secret JSON file.
     * The clientSecrets value is initialized at construction time, and is never null.
     */
    public static String getClientId() {
        return clientSecrets.getWeb().getClientId();
    }

    /**
     * This is the Client secret that you generated in the API Console.  It is stored
     * in the client secret JSON file.
     * The clientSecrets value is initialized at construction time, and is never null.
     */
    public static String getClientSecret() {
        return clientSecrets.getWeb().getClientSecret();
    }

    /**
     * Reads in the client_secrets.json file and returns the constructed GoogleClientSecrets
     * object. This method is called lazily to set the client ID,
     * client secret, and redirect uri.
     *
     * @throws RuntimeException if there is an IOException reading the configuration
     */
    public static synchronized void initClientSecretInfo() {
        if (clientSecrets == null) {
            try {
                Reader reader = new FileReader("client_secrets.json");
                clientSecrets = GoogleClientSecrets.load(Services.JSON_FACTORY, reader);
            } catch (IOException e) {
                throw new RuntimeException("Cannot initialize client secrets", e);
            }
        }
    }

    /**
     * Create a GoogleCredential from the provided access and refresh tokens.
     */
    public static GoogleCredential createCredential(String accessToken, String refreshToken) {
        return new GoogleCredential.Builder()
                .setJsonFactory(Services.JSON_FACTORY)
                .setTransport(Services.TRANSPORT)
                .setClientSecrets(clientSecrets)
                .addRefreshListener(new Authenticate.InvalidateRefreshTokenOnExpired())
                .build()
                .setAccessToken(accessToken)
                .setRefreshToken(refreshToken);
    }

}
