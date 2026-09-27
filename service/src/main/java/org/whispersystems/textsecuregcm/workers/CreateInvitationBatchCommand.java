/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.workers;

import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Environment;
import java.time.Clock;
import java.time.Duration;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.receipts.ServerZkReceiptOperations;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.storage.InvitationsManager;

/** Controlled operator command. Invitation plaintext is emitted once to stdout and is never logged or stored. */
public class CreateInvitationBatchCommand extends AbstractCommandWithDependencies {
  public CreateInvitationBatchCommand() {
    super(new Application<>() {
      @Override
      public void run(final WhisperServerConfiguration configuration, final Environment environment) {}
    }, "create-invitation-batch", "Create a batch of single-use numberless-registration invitations");
  }

  @Override
  public void configure(final Subparser subparser) {
    super.configure(subparser);
    subparser.addArgument("--batch-id").required(true);
    subparser.addArgument("--count").type(Integer.class).required(true);
    subparser.addArgument("--valid-days").type(Integer.class).setDefault(7);
  }

  @Override
  protected void run(final Environment environment, final Namespace namespace,
      final WhisperServerConfiguration configuration, final CommandDependencies dependencies) throws Exception {
    final Clock clock = Clock.systemUTC();
    final int validDays = namespace.getInt("valid_days");
    if (validDays < 1 || validDays > 365) {
      throw new IllegalArgumentException("valid-days must be between 1 and 365");
    }
    final ServerSecretParams params = new ServerSecretParams(configuration.getGroupsZkConfig().serverSecret().value());
    final InvitationsManager manager = new InvitationsManager(
        configuration.getDynamoDbTables().getIssuedReceipts().getTableName(),
        dependencies.dynamoDbClient(),
        configuration.getDynamoDbTables().getIssuedReceipts().getGenerator(),
        new ServerZkReceiptOperations(params),
        clock);

    manager.createBatch(namespace.getString("batch_id"), namespace.getInt("count"),
            clock.instant().plus(Duration.ofDays(validDays)))
        .forEach(System.out::println);
  }
}
