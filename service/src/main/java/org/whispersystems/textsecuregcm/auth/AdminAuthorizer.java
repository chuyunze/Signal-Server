/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import org.whispersystems.textsecuregcm.configuration.AdminConfiguration;

public class AdminAuthorizer {
  public enum Role { INVITATION_OPERATOR, ACCOUNT_OPERATOR, AUDITOR, SUPER_ADMIN }

  public record Principal(String subject, Set<Role> roles, boolean recentlyMfaAuthenticated) {
    public void require(final Role role) {
      if (!roles.contains(role) && !roles.contains(Role.SUPER_ADMIN)) {
        throw new ForbiddenException();
      }
    }

    public void requireRecentMfa() {
      if (!recentlyMfaAuthenticated) {
        throw new ForbiddenException("recent MFA authentication required");
      }
    }
  }

  private static final Duration HIGH_RISK_AUTH_AGE = Duration.ofMinutes(5);
  private final JWTVerifier verifier;
  private final Clock clock;

  public AdminAuthorizer(final AdminConfiguration configuration, final Clock clock) {
    configuration.validateEnabled();
    final Verification verification = JWT.require(Algorithm.HMAC512(configuration.gatewayTokenSecret().value()))
        .withIssuer(configuration.issuer()).withAudience(configuration.audience()).acceptLeeway(30);
    this.verifier = ((JWTVerifier.BaseVerification) verification).build(clock);
    this.clock = clock;
  }

  public Principal authenticate(final String authorization) {
    if (authorization == null || !authorization.startsWith("Bearer ")) {
      throw new NotAuthorizedException("Bearer");
    }
    try {
      final DecodedJWT jwt = verifier.verify(authorization.substring(7));
      final List<String> rawRoles = jwt.getClaim("roles").asList(String.class);
      final EnumSet<Role> roles = EnumSet.noneOf(Role.class);
      if (rawRoles != null) {
        rawRoles.forEach(value -> {
          try {
            roles.add(Role.valueOf(value));
          } catch (final IllegalArgumentException ignored) {
            // Unknown roles confer no authority.
          }
        });
      }
      final List<String> amr = jwt.getClaim("amr").asList(String.class);
      final Instant authenticatedAt = jwt.getClaim("auth_time").asInstant();
      final boolean recentMfa = amr != null && amr.contains("mfa") && authenticatedAt != null
          && authenticatedAt.plus(HIGH_RISK_AUTH_AGE).isAfter(clock.instant());
      return new Principal(jwt.getSubject(), Set.copyOf(roles), recentMfa);
    } catch (final JWTVerificationException | IllegalArgumentException e) {
      throw new NotAuthorizedException("Bearer");
    }
  }
}
