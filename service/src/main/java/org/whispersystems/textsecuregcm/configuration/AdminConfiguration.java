/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.configuration;

import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/** Authentication boundary between the OIDC-aware admin gateway and this service. */
public record AdminConfiguration(boolean enabled, @Nullable String issuer, @Nullable String audience,
                                 @Nullable SecretString gatewayTokenSecret) {
  public static final AdminConfiguration DISABLED = new AdminConfiguration(false, null, null, null);

  public void validateEnabled() {
    if (enabled && (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()
        || gatewayTokenSecret == null || gatewayTokenSecret.value().length() < 32)) {
      throw new IllegalArgumentException("enabled admin service requires issuer, audience, and a 32+ character secret");
    }
  }
}
