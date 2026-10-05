/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import java.io.InputStream;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;
import org.whispersystems.textsecuregcm.s3.S3ObjectMonitor;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

/**
 * Disables an optional S3-backed data source while retaining the caller's configured fallback value.
 */
@JsonTypeName("disabled")
public class DisabledS3ObjectMonitorFactory implements S3ObjectMonitorFactory {

  @Override
  public S3ObjectMonitor build(final AwsCredentialsProvider awsCredentialsProvider,
      final ScheduledExecutorService refreshExecutorService) {
    return new DisabledS3ObjectMonitor(awsCredentialsProvider);
  }

  private static class DisabledS3ObjectMonitor extends S3ObjectMonitor {

    private DisabledS3ObjectMonitor(final AwsCredentialsProvider awsCredentialsProvider) {
      super(awsCredentialsProvider, "disabled", "disabled", "disabled", 0, null, null);
    }

    @Override
    public synchronized void start(final Consumer<InputStream> changeListener) {
      // Intentionally empty. The S3MonitoringSupplier keeps its configured fallback value.
    }

    @Override
    public synchronized void stop() {
      // Nothing was scheduled.
    }
  }
}
