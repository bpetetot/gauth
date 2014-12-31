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

package fr.mhz.bookie;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Simple servlet that sets the metadata.
 */
public class StaticServlet extends HttpServlet {

  /**
   * Logger for the Authenticate class.
   */
  Logger logger = Logger.getLogger("StaticServlet");

  /**
   * Sets the metadata for the intended in the page, and then serves the page
   * by forwarding the request.
   */
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

    try {

      request.getRequestDispatcher("/index.html").forward(request, response);

    } catch (ServletException e) {
      logger.log(Level.INFO, "Failed to forward the request; return 500", e);
      response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      response.getWriter().print("500 while attempting to forward to index.html");
    }
  }

}
