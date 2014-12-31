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

import fr.mhz.bookie.model.User;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Ensures a user is authenticated and authorized before continuing with the intended API call.
 *
 * @author joannasmith@google.com (Joanna Smith)
 */
public class AuthenticatedFilter implements Filter {

    Authenticate authenticator;
    ExecutorService executor = Executors.newSingleThreadExecutor();

    public AuthenticatedFilter() {
        authenticator = new Authenticate(executor);
    }

    AuthenticatedFilter(Authenticate authenticator) {
        this.authenticator = authenticator;
    }

    /**
     * @see javax.servlet.Filter#init(javax.servlet.FilterConfig)
     */
    @Override
    public void init(FilterConfig config) throws ServletException {
    }

    /**
     * Closes out the open ExecutorService resource.
     *
     * @see javax.servlet.Filter#destroy()
     */
    @Override
    public void destroy() {
        executor.shutdown();
    }

    /**
     * Called before the API endpoint servlet; verifies that a user is authenticated before
     * processing the API call.
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) {
        // We propagate ClassCastExceptions here, since this Filter should only ever be used with
        // HttpServlets.
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String sessionId = request.getSession().getId();

        System.out.println("AuthenticatedFilter> " + sessionId);

        User user = authenticator.requireAuthentication(sessionId, request, response);

        System.out.println("User " + user);

        // If the authenticator was successful, we continue to the API endpoint servlet for
        // the original call.
        if (user != null) {
            try {
                chain.doFilter(request, response);
            } catch (IOException e) {
                // Likely a temporary network error
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            } catch (ServletException e) {
                // Something went wrong with Jetty serving requests.
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }
    }
}
