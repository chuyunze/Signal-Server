/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.controllers;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@Path("/admin")
public class AdminConsoleController {
  @GET
  @Produces("text/html; charset=utf-8")
  public Response index() throws IOException {
    try (InputStream input = getClass().getResourceAsStream("/admin/index.html")) {
      if (input == null) throw new NotFoundException();
      return Response.ok(new String(input.readAllBytes(), StandardCharsets.UTF_8))
          .header("Cache-Control", "no-store")
          .header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; "
              + "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
          .header("X-Frame-Options", "DENY")
          .header("X-Content-Type-Options", "nosniff")
          .build();
    }
  }
}
