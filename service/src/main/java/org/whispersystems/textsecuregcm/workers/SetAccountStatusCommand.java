/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.workers;

import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Environment;
import java.time.Clock;
import java.util.Locale;
import java.util.UUID;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountStatus;
import org.whispersystems.textsecuregcm.storage.AccountStatusManager;

/** Controlled operator command used until the RBAC-protected administration service is delivered in phase 7. */
public class SetAccountStatusCommand extends AbstractCommandWithDependencies {
  public SetAccountStatusCommand() {
    super(new Application<>() {
      @Override
      public void run(final WhisperServerConfiguration configuration, final Environment environment) {}
    }, "set-account-status", "Suspend, disable, or reactivate an account by ACI");
  }

  @Override
  public void configure(final Subparser subparser) {
    super.configure(subparser);
    subparser.addArgument("--account-id").required(true);
    subparser.addArgument("--status").required(true).choices("ACTIVE", "SUSPENDED", "DISABLED");
    subparser.addArgument("--actor").required(true);
    subparser.addArgument("--reason").required(true);
  }

  @Override
  protected void run(final Environment environment, final Namespace namespace,
      final WhisperServerConfiguration configuration, final CommandDependencies dependencies) {
    final UUID accountIdentifier = UUID.fromString(namespace.getString("account_id"));
    final AccountStatus target = AccountStatus.valueOf(namespace.getString("status").toUpperCase(Locale.ROOT));
    final Account updated = new AccountStatusManager(dependencies.accountsManager(), Clock.systemUTC()).transition(
        accountIdentifier,
        target,
        namespace.getString("actor"),
        namespace.getString("reason"));
    System.out.printf("account=%s status=%s version=%d%n", accountIdentifier,
        updated.getAccountStatus(), updated.getAccountStatusVersion());
  }
}
