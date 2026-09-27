/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

/** Administrative access state. Missing state on legacy records is treated as ACTIVE. */
public enum AccountStatus {
  ACTIVE,
  SUSPENDED,
  DISABLED,
  PURGED;

  public boolean permitsServiceAccess() {
    return this == ACTIVE;
  }

  public boolean mayTransitionTo(final AccountStatus target) {
    if (this == PURGED) {
      return false;
    }
    return target != PURGED || this == DISABLED;
  }
}
