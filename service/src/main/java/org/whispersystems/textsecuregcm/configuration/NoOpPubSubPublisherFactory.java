/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.cloud.pubsub.v1.PublisherInterface;
import com.google.pubsub.v1.PubsubMessage;
import java.io.IOException;

/**
 * [SELFHOST] 空实现的 Google Pub/Sub 发布者工厂。
 *
 * <p>官方 {@link DefaultPubSubPublisherFactory} 启动时必须解析真实的 Google 外部账号凭证 JSON;
 * 自建部署没有 GCP 凭证, 通话质量调查与 Braintree 支付等 Pub/Sub 出口均不需要,
 * 配置 {@code type: noop} 后消息直接丢弃, 避免凭证解析失败导致服务启动中断。
 */
@JsonTypeName("noop")
public class NoOpPubSubPublisherFactory implements PubSubPublisherFactory {

  @Override
  public PublisherInterface build() throws IOException {
    return new PublisherInterface() {
      @Override
      public ApiFuture<String> publish(final PubsubMessage message) {
        return ApiFutures.immediateFuture("noop");
      }
    };
  }
}
