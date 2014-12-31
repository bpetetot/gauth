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

package fr.mhz.bookie.auth;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponseException;
import com.google.inject.Singleton;
import fr.mhz.bookie.model.User;
import fr.mhz.bookie.services.Services;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides an API endpoint for permanently disconnecting a user from the app.
 *
 *   POST /api/disconnect
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
@Singleton
public class DisconnectServlet extends HttpServlet {
  /**
   * Logger for the Authenticate class.
   */
  Logger logger = Logger.getLogger("DisconnectServlet");

  /**
   * For use in verifying access tokens, as the client library currently does not provide
   * a validation method for access tokens.
   */
  private static final String TOKEN_INFO_REVOKE_ENDPOINT = "https://accounts.google.com/o/oauth2/revoke?token=%s";

  /**
   * Exposed as `POST /api/disconnect`.
   *
   * Deletes cached Google+ data for the current user.
   * Revokes any currently held Google OAuth tokens.
   * Disassociates any authentication information with the current session.
   * Deletes all haikus by this user.
   *
   * @throws java.io.IOException if the response fails to fetch its writer
   */
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String sessionId = request.getSession().getId();
    User user = Services.userDao.loadUserWithSessionId(sessionId);

    if (user == null) {
      // Somehow, the session is unauthenticated.
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      return;
    }

    try {
      if (user.getAccessToken() != null) {
        revokeToken(user.getAccessToken());
      }
    } catch (IOException e) {
      logger.log(Level.INFO, "Revoke token HTTP request failed; return 500", e);
      // The HTTP request was malformed or could not be completed, likely due to a network error.
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return;
    }

    // Delete user data within the app
    user.setAccessToken(null);
    user.setRefreshToken(null);
    Services.userDao.updateUser(user);

    logger.log(Level.INFO, "Disconnect succeeded");
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(Services.JSON_MIMETYPE);
    response.getWriter().print("{ \"msg\": \"Disconnect complete\" }");
  }

  private void revokeToken(String token) throws IOException {
    // Form a request to the token info revoke endpoint, since the Java client library does not
    // provide a method to invalidate an access token.
    try {
      Services.TRANSPORT.createRequestFactory()
          .buildGetRequest(new GenericUrl(String.format(TOKEN_INFO_REVOKE_ENDPOINT, token)))
          .execute();
    } catch (HttpResponseException e) {
      // The response code from the GET request was an error code. This could mean that the token
      // is already invalid.
      logger.log(Level.INFO, "Revoke token HTTP request returned an error code.", e);
    }
  }
}
