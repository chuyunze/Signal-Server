/* Copyright 2026 Signal Messenger, LLC; SPDX-License-Identifier: AGPL-3.0-only */
package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.receipts.ClientZkReceiptOperations;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialRequestContext;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialResponse;
import org.signal.libsignal.zkgroup.receipts.ReceiptSerial;
import org.signal.libsignal.zkgroup.receipts.ServerZkReceiptOperations;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemResponse;
import software.amazon.awssdk.services.dynamodb.paginators.ScanIterable;

class InvitationsManagerTest {
  private static final Instant NOW = Instant.parse("2026-09-26T00:00:00Z");
  private ClientZkReceiptOperations clientOperations;
  private DynamoDbClient dynamoDbClient;
  private InvitationsManager manager;

  @BeforeEach
  void setUp() {
    final ServerSecretParams params = ServerSecretParams.generate();
    clientOperations = new ClientZkReceiptOperations(params.getPublicParams());
    dynamoDbClient = mock(DynamoDbClient.class);
    manager = new InvitationsManager("invitations", dynamoDbClient, TestRandomUtil.nextBytes(32),
        new ServerZkReceiptOperations(params), Clock.fixed(NOW, ZoneOffset.UTC));
  }

  @Test
  void batchCreationPersistsDigestsNotPlaintext() {
    when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(PutItemResponse.builder().build());
    final var codes = manager.createBatch("batch-1", 2, NOW.plusSeconds(3600));
    assertThat(codes).hasSize(2).doesNotHaveDuplicates();
    final ArgumentCaptor<PutItemRequest> captor = ArgumentCaptor.forClass(PutItemRequest.class);
    verify(dynamoDbClient, times(2)).putItem(captor.capture());
    assertThat(captor.getAllValues()).allSatisfy(request -> {
      assertThat(request.item().get("A").s()).startsWith("invitation:");
      assertThat(request.item().values()).noneMatch(value -> value.s() != null && codes.contains(value.s()));
    });
  }

  @Test
  void claimIsSingleUseAndIdempotentForSameRequest() throws Exception {
    when(dynamoDbClient.putItem(any(PutItemRequest.class))).thenReturn(PutItemResponse.builder().build());
    final String code = manager.createBatch("batch-1", 1, NOW.plusSeconds(3600)).getFirst();
    final ReceiptCredentialRequestContext context = requestContext();
    final Map<String, AttributeValue> claimedItem = new HashMap<>();
    when(dynamoDbClient.updateItem(any(UpdateItemRequest.class)))
        .thenAnswer(invocation -> {
          final UpdateItemRequest request = invocation.getArgument(0);
          claimedItem.put("IS", AttributeValue.fromS("CLAIMED"));
          claimedItem.put("IR", request.expressionAttributeValues().get(":request"));
          claimedItem.put("IC", request.expressionAttributeValues().get(":response"));
          return UpdateItemResponse.builder().build();
        })
        .thenThrow(ConditionalCheckFailedException.builder().build());
    when(dynamoDbClient.getItem(any(GetItemRequest.class)))
        .thenAnswer(_ -> GetItemResponse.builder().item(claimedItem).build());

    final byte[] response = manager.claim(code, context.getRequest().serialize());
    assertThat(manager.claim(code, context.getRequest().serialize())).isEqualTo(response);
    final var credential = clientOperations.receiveReceiptCredential(context, new ReceiptCredentialResponse(response));
    assertThat(credential.getReceiptLevel()).isEqualTo(300);
  }

  @Test
  void claimedCodeRejectsAnotherRequest() throws Exception {
    when(dynamoDbClient.updateItem(any(UpdateItemRequest.class)))
        .thenThrow(ConditionalCheckFailedException.builder().build());
    when(dynamoDbClient.getItem(any(GetItemRequest.class))).thenReturn(GetItemResponse.builder().item(Map.of(
        "IS", AttributeValue.fromS("CLAIMED"),
        "IR", AttributeValue.fromB(software.amazon.awssdk.core.SdkBytes.fromByteArray(TestRandomUtil.nextBytes(32))),
        "IC", AttributeValue.fromB(software.amazon.awssdk.core.SdkBytes.fromByteArray(TestRandomUtil.nextBytes(32)))))
        .build());
    assertThatThrownBy(() -> manager.claim("abcdefghijklmnop", requestContext().getRequest().serialize()))
        .isExactlyInstanceOf(InvitationsManager.InvitationUnavailableException.class);
  }

  @Test
  void deletingBatchRevokesAvailableInvitationsAndRetainsClaimedRecords() {
    final ScanIterable scan = mock(ScanIterable.class);
    when(dynamoDbClient.scanPaginator(any(software.amazon.awssdk.services.dynamodb.model.ScanRequest.class)))
        .thenReturn(scan);
    when(scan.items()).thenReturn(() -> List.of(
        Map.of("A", AttributeValue.fromS("invitation:available"), "IB", AttributeValue.fromS("batch-1")),
        Map.of("A", AttributeValue.fromS("invitation:claimed"), "IB", AttributeValue.fromS("batch-1")))
        .iterator());
    when(dynamoDbClient.updateItem(any(UpdateItemRequest.class)))
        .thenReturn(UpdateItemResponse.builder().build())
        .thenThrow(ConditionalCheckFailedException.builder().build())
        .thenReturn(UpdateItemResponse.builder().build());

    assertThat(manager.deleteBatch("batch-1"))
        .isEqualTo(new InvitationsManager.DeleteBatchResult(2, 1));

    final ArgumentCaptor<UpdateItemRequest> updates = ArgumentCaptor.forClass(UpdateItemRequest.class);
    verify(dynamoDbClient, times(3)).updateItem(updates.capture());
    assertThat(updates.getAllValues().get(0).updateExpression())
        .isEqualTo("SET #state = :revoked, #hidden = :hidden");
    assertThat(updates.getAllValues().get(2).updateExpression()).isEqualTo("SET #hidden = :hidden");
  }

  private ReceiptCredentialRequestContext requestContext() throws Exception {
    return clientOperations.createReceiptCredentialRequestContext(
        new ReceiptSerial(TestRandomUtil.nextBytes(ReceiptSerial.SIZE)));
  }
}
