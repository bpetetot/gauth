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

package fr.mhz.bookie.api;

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
 * Provides an API endpoint for retrieving the profile of the currently logged in user.
 * <p/>
 * GET /api/users/me
 */
@Singleton
public class UserServlet extends HttpServlet {

    /**
     * Logger for the UserServlet class.
     */
    Logger logger = Logger.getLogger("UserServlet");

    /**
     * Exposed as `GET /api/users/me`.
     * <p/>
     * Returns a user resource for the currently authenticated user.
     * <p/>
     * {
     * "id":"",
     * "google_plus_id":"",
     * "google_display_name":"",
     * "google_photo_url":"",
     * "google_profile_url":"",
     * "last_updated":""
     * }
     *
     * @throws java.io.IOException if the response fails to fetch its writer
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String sessionId = request.getSession().getId();

        User sessionUser = Services.userDao.loadUserWithSessionId(sessionId);
        if (sessionUser == null) {
            logger.log(Level.INFO, "The session is unauthenticated; return 403", sessionId);
            // Somehow, the session is unauthenticated.
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        logger.log(Level.INFO, "User info request succeeded for user: " + sessionUser.getUserId());

        response.setContentType(Services.JSON_MIMETYPE);
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().print(sessionUser.toJson());
    }
}
