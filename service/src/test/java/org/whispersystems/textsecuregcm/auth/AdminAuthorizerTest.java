/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.auth.AdminAuthorizer.Role;
import org.whispersystems.textsecuregcm.configuration.AdminConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.util.TestClock;

class AdminAuthorizerTest {
  private static final String SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  private static final Instant NOW = Instant.parse("2026-09-27T08:00:00Z");
  private final TestClock clock = TestClock.pinned(NOW);
  private final AdminAuthorizer authorizer = new AdminAuthorizer(
      new AdminConfiguration(true, "https://admin-id.example", "signal-admin", new SecretString(SECRET)), clock);

  @Test
  void verifiesRoleAndRecentMfa() {
    final var principal = authorizer.authenticate(
        "Bearer " + token(List.of("ACCOUNT_OPERATOR"), List.of("pwd", "mfa"), NOW));

    assertThat(principal.subject()).isEqualTo("operator-1");
    assertThat(principal.roles()).containsExactly(Role.ACCOUNT_OPERATOR);
    assertThat(principal.recentlyMfaAuthenticated()).isTrue();
    principal.require(Role.ACCOUNT_OPERATOR);
    principal.requireRecentMfa();
  }

  @Test
  void rejectsSignalOrInvalidBearerCredentials() {
    assertThrows(NotAuthorizedException.class, () -> authorizer.authenticate("Basic account:password"));
    assertThrows(NotAuthorizedException.class, () -> authorizer.authenticate("Bearer invalid"));
  }

  @Test
  void rejectsMissingRoleAndStaleMfa() {
    final var principal = authorizer.authenticate(
        "Bearer " + token(List.of("AUDITOR"), List.of("mfa"), NOW.minusSeconds(301)));

    assertThrows(ForbiddenException.class, () -> principal.require(Role.ACCOUNT_OPERATOR));
    assertThrows(ForbiddenException.class, principal::requireRecentMfa);
  }

  @Test
  void superAdminHasEveryRole() {
    final var principal = authorizer.authenticate("Bearer " + token(List.of("SUPER_ADMIN"), List.of("mfa"), NOW));
    principal.require(Role.ACCOUNT_OPERATOR);
    principal.require(Role.INVITATION_OPERATOR);
    principal.require(Role.AUDITOR);
  }

  private static String token(final List<String> roles, final List<String> amr, final Instant authTime) {
    return JWT.create().withIssuer("https://admin-id.example").withAudience("signal-admin").withSubject("operator-1")
        .withIssuedAt(Date.from(NOW.minusSeconds(10))).withExpiresAt(Date.from(NOW.plusSeconds(60)))
        .withClaim("roles", roles).withClaim("amr", amr).withClaim("auth_time", Date.from(authTime))
        .sign(Algorithm.HMAC512(SECRET));
  }
}
