/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

import java.time.Clock;
import java.util.Objects;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Applies audited account-state transitions and disconnects newly restricted accounts. */
public class AccountStatusManager {
  private static final Logger logger = LoggerFactory.getLogger(AccountStatusManager.class);

  private final AccountsManager accountsManager;
  private final Clock clock;

  public AccountStatusManager(final AccountsManager accountsManager, final Clock clock) {
    this.accountsManager = accountsManager;
    this.clock = clock;
  }

  public Account transition(final UUID accountIdentifier, final AccountStatus target,
      final String actor, final String reason) {
    Objects.requireNonNull(target);
    if (actor == null || actor.isBlank() || reason == null || reason.isBlank()) {
      throw new IllegalArgumentException("actor and reason are required");
    }

    final Account current = accountsManager.getByAccountIdentifier(accountIdentifier)
        .orElseThrow(() -> new IllegalArgumentException("account not found"));
    final AccountStatus previous = current.getAccountStatus();
    if (previous == target) {
      return current;
    }
    if (!previous.mayTransitionTo(target)) {
      throw new IllegalStateException("invalid account status transition: " + previous + " -> " + target);
    }
    if (target == AccountStatus.PURGED) {
      throw new IllegalStateException("PURGED requires the destructive account deletion workflow");
    }

    final Account updated = accountsManager.update(accountIdentifier, account ->
        account.setAccountStatus(target, account.getAccountStatusVersion() + 1, clock.instant()));

    logger.info("account_status_changed account={} previous={} target={} version={} actor={} reason={}",
        accountIdentifier, previous, target, updated.getAccountStatusVersion(), sanitize(actor), sanitize(reason));

    if (!target.permitsServiceAccess()) {
      accountsManager.disconnectAllDevices(updated);
    }
    return updated;
  }

  private static String sanitize(final String value) {
    final String sanitized = value.replaceAll("[\\r\\n\\t]", " ");
    return sanitized.substring(0, Math.min(sanitized.length(), 256));
  }
}
