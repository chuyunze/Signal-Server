/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.net.URI;
import java.time.Duration;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.metrics.MetricPublisher;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

/**
 * [SELFHOST] DynamoDB Local 客户端工厂。
 *
 * <p>官方上游仅提供 {@link DynamoDbClientConfiguration}（type=default），指向 AWS 区域端点；
 * 自建部署使用容器内 DynamoDB Local，需要通过 endpointOverride 指向 {@code http://dynamodb:8000}。
 * 配置示例：
 * <pre>
 * dynamoDbClient:
 *   type: local
 *   endpoint: http://dynamodb:8000
 *   region: us-east-1
 * </pre>
 */
@JsonTypeName("local")
public record LocalDynamoDbClientConfiguration(@NotBlank String region,
                                               @NotBlank String endpoint,
                                               @NotNull Duration clientExecutionTimeout,
                                               @NotNull Duration clientRequestTimeout,
                                               @Positive int maxConnections) implements DynamoDbClientFactory {

  public LocalDynamoDbClientConfiguration {
    if (clientExecutionTimeout == null) {
      clientExecutionTimeout = Duration.ofSeconds(30);
    }

    if (clientRequestTimeout == null) {
      clientRequestTimeout = Duration.ofSeconds(10);
    }

    if (maxConnections == 0) {
      maxConnections = 50;
    }
  }

  @Override
  public DynamoDbClient buildSyncClient(final AwsCredentialsProvider credentialsProvider, final MetricPublisher metricPublisher) {
    return DynamoDbClient.builder()
        .endpointOverride(URI.create(endpoint()))
        .region(Region.of(region()))
        .credentialsProvider(credentialsProvider)
        .overrideConfiguration(ClientOverrideConfiguration.builder()
            .apiCallTimeout(clientExecutionTimeout())
            .apiCallAttemptTimeout(clientRequestTimeout())
            .addMetricPublisher(metricPublisher)
            .build())
        .httpClientBuilder(AwsCrtHttpClient.builder()
            .maxConcurrency(maxConnections()))
        .build();
  }

  @Override
  public DynamoDbAsyncClient buildAsyncClient(final AwsCredentialsProvider credentialsProvider, final MetricPublisher metricPublisher) {
    return DynamoDbAsyncClient.builder()
        .endpointOverride(URI.create(endpoint()))
        .region(Region.of(region()))
        .credentialsProvider(credentialsProvider)
        .overrideConfiguration(ClientOverrideConfiguration.builder()
            .apiCallTimeout(clientExecutionTimeout())
            .apiCallAttemptTimeout(clientRequestTimeout())
            .addMetricPublisher(metricPublisher)
            .build())
        .httpClientBuilder(NettyNioAsyncHttpClient.builder()
            .maxConcurrency(maxConnections()))
        .build();
  }
}
