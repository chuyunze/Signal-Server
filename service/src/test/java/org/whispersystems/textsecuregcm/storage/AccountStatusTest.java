/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class AccountStatusTest {

  @Test
  void legacyAccountDefaultsToActive() {
    final Account account = new Account();

    assertThat(account.getAccountStatus()).isEqualTo(AccountStatus.ACTIVE);
    assertThat(account.getAccountStatusVersion()).isZero();
    assertThat(account.isServiceAccessAllowed()).isTrue();
  }

  @Test
  void suspendedAndDisabledAccountsCannotAccessTheService() {
    final Account account = new Account();

    account.setAccountStatus(AccountStatus.SUSPENDED, 1, Instant.EPOCH);
    assertThat(account.isServiceAccessAllowed()).isFalse();

    account.setAccountStatus(AccountStatus.DISABLED, 2, Instant.EPOCH.plusSeconds(1));
    assertThat(account.isServiceAccessAllowed()).isFalse();
  }

  @Test
  void purgedAccountCannotTransitionAndOnlyDisabledMayBePurged() {
    assertThat(AccountStatus.ACTIVE.mayTransitionTo(AccountStatus.PURGED)).isFalse();
    assertThat(AccountStatus.SUSPENDED.mayTransitionTo(AccountStatus.PURGED)).isFalse();
    assertThat(AccountStatus.DISABLED.mayTransitionTo(AccountStatus.PURGED)).isTrue();
    assertThat(AccountStatus.PURGED.mayTransitionTo(AccountStatus.ACTIVE)).isFalse();
  }
}
