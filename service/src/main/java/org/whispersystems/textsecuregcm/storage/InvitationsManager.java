/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

import static org.whispersystems.textsecuregcm.util.AttributeValues.b;
import static org.whispersystems.textsecuregcm.util.AttributeValues.n;
import static org.whispersystems.textsecuregcm.util.AttributeValues.s;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialRequest;
import org.signal.libsignal.zkgroup.receipts.ReceiptCredentialResponse;
import org.signal.libsignal.zkgroup.receipts.ServerZkReceiptOperations;
import org.whispersystems.textsecuregcm.subscriptions.ReceiptLevel;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

/** Stores one-time invitation state without ever persisting the invitation plaintext. */
public class InvitationsManager {
  private static final String KEY = "A";
  private static final String STATE = "IS";
  private static final String BATCH = "IB";
  private static final String EXPIRES = "IE";
  private static final String REQUEST_TAG = "IR";
  private static final String RESPONSE = "IC";
  private static final String CLAIMED_AT = "IT";
  private static final String CREATED_AT = "II";
  private static final String AVAILABLE = "AVAILABLE";
  private static final String CLAIMED = "CLAIMED";
  private static final String REVOKED = "REVOKED";
  private static final Duration RECEIPT_LIFETIME = Duration.ofDays(30);

  private final String table;
  private final DynamoDbClient dynamoDbClient;
  private final byte[] hmacKey;
  private final ServerZkReceiptOperations receiptOperations;
  private final Clock clock;
  private final SecureRandom secureRandom;

  public InvitationsManager(final String table, final DynamoDbClient dynamoDbClient, final byte[] hmacKey,
      final ServerZkReceiptOperations receiptOperations, final Clock clock) {
    this(table, dynamoDbClient, hmacKey, receiptOperations, clock, new SecureRandom());
  }

  InvitationsManager(final String table, final DynamoDbClient dynamoDbClient, final byte[] hmacKey,
      final ServerZkReceiptOperations receiptOperations, final Clock clock, final SecureRandom secureRandom) {
    this.table = Objects.requireNonNull(table);
    this.dynamoDbClient = Objects.requireNonNull(dynamoDbClient);
    this.hmacKey = Objects.requireNonNull(hmacKey).clone();
    this.receiptOperations = Objects.requireNonNull(receiptOperations);
    this.clock = Objects.requireNonNull(clock);
    this.secureRandom = Objects.requireNonNull(secureRandom);
  }

  /** Returns plaintext codes once; callers must deliver them securely and must not log them. */
  public List<String> createBatch(final String batchId, final int count, final Instant expiresAt) {
    if (batchId == null || batchId.isBlank() || batchId.length() > 128 || count < 1 || count > 10_000
        || !expiresAt.isAfter(clock.instant())) {
      throw new IllegalArgumentException("invalid invitation batch");
    }
    final List<String> codes = new ArrayList<>(count);
    while (codes.size() < count) {
      final byte[] random = new byte[20];
      secureRandom.nextBytes(random);
      final String code = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
      try {
        dynamoDbClient.putItem(PutItemRequest.builder()
            .tableName(table)
            .item(Map.of(KEY, s(storageKey(code)), STATE, s(AVAILABLE), BATCH, s(batchId),
                EXPIRES, n(expiresAt.getEpochSecond()), CREATED_AT, n(clock.instant().getEpochSecond())))
            .conditionExpression("attribute_not_exists(#key)")
            .expressionAttributeNames(Map.of("#key", KEY))
            .build());
        codes.add(code);
      } catch (final ConditionalCheckFailedException ignored) {
        // Cryptographically improbable collision; generate another code.
      }
    }
    return List.copyOf(codes);
  }

  public byte[] claim(final String invitationCode, final byte[] serializedRequest)
      throws InvitationUnavailableException, InvalidInputException, VerificationFailedException {
    final ReceiptCredentialRequest request = new ReceiptCredentialRequest(serializedRequest);
    final String key = storageKey(invitationCode);
    final byte[] requestTag = hmac("invitation-request", serializedRequest);
    final Instant now = clock.instant();
    final Instant receiptExpiration = now.plus(RECEIPT_LIFETIME).truncatedTo(ChronoUnit.DAYS);
    final ReceiptCredentialResponse response = receiptOperations.issueReceiptCredential(request,
        receiptExpiration.getEpochSecond(), ReceiptLevel.LOGIN.getValue());
    final byte[] serializedResponse = response.serialize();

    try {
      dynamoDbClient.updateItem(UpdateItemRequest.builder()
          .tableName(table)
          .key(Map.of(KEY, s(key)))
          .conditionExpression("#state = :available AND #expires > :now")
          .updateExpression("SET #state = :claimed, #request = :request, #response = :response, #claimedAt = :now")
          .expressionAttributeNames(Map.of("#state", STATE, "#expires", EXPIRES, "#request", REQUEST_TAG,
              "#response", RESPONSE, "#claimedAt", CLAIMED_AT))
          .expressionAttributeValues(Map.of(":available", s(AVAILABLE), ":claimed", s(CLAIMED),
              ":now", n(now.getEpochSecond()), ":request", b(requestTag), ":response", b(serializedResponse)))
          .build());
      return serializedResponse;
    } catch (final ConditionalCheckFailedException ignored) {
      final Map<String, AttributeValue> item = get(key);
      if (CLAIMED.equals(string(item, STATE)) && constantTimeEquals(bytes(item, REQUEST_TAG), requestTag)) {
        return bytes(item, RESPONSE);
      }
      throw new InvitationUnavailableException();
    }
  }

  public boolean revoke(final String invitationCode) {
    return changeAvailableInvitation(invitationCode, "SET #state = :revoked",
        Map.of(":revoked", s(REVOKED)), Map.of("#state", STATE));
  }

  public boolean extend(final String invitationCode, final Instant expiresAt) {
    if (!expiresAt.isAfter(clock.instant())) {
      throw new IllegalArgumentException("expiration must be in the future");
    }
    return changeAvailableInvitation(invitationCode, "SET #expires = :expires",
        Map.of(":expires", n(expiresAt.getEpochSecond())), Map.of("#expires", EXPIRES));
  }

  public record BatchSummary(String batchId, long available, long claimed, long revoked, long expired,
                             Instant earliestCreation, Instant latestExpiration) {}

  /** Returns aggregate metadata only; invitation plaintext is never recoverable from storage. */
  public List<BatchSummary> listBatches() {
    record Mutable(long[] counts, Instant[] bounds) {}
    final Map<String, Mutable> batches = new java.util.HashMap<>();
    dynamoDbClient.scanPaginator(ScanRequest.builder().tableName(table)
        .filterExpression("attribute_exists(#batch)")
        .expressionAttributeNames(Map.of("#batch", BATCH)).build()).items().forEach(item -> {
          final String batch = string(item, BATCH);
          if (batch == null) return;
          final Mutable summary = batches.computeIfAbsent(batch,
              ignored -> new Mutable(new long[4], new Instant[] { Instant.MAX, Instant.MIN }));
          final Instant expires = Instant.ofEpochSecond(Long.parseLong(item.get(EXPIRES).n()));
          final String state = string(item, STATE);
          if (AVAILABLE.equals(state) && !expires.isAfter(clock.instant())) summary.counts()[3]++;
          else if (AVAILABLE.equals(state)) summary.counts()[0]++;
          else if (CLAIMED.equals(state)) summary.counts()[1]++;
          else if (REVOKED.equals(state)) summary.counts()[2]++;
          if (item.containsKey(CREATED_AT)) {
            final Instant created = Instant.ofEpochSecond(Long.parseLong(item.get(CREATED_AT).n()));
            if (created.isBefore(summary.bounds()[0])) summary.bounds()[0] = created;
          }
          if (expires.isAfter(summary.bounds()[1])) summary.bounds()[1] = expires;
        });
    return batches.entrySet().stream().map(entry -> {
      final Mutable value = entry.getValue();
      return new BatchSummary(entry.getKey(), value.counts()[0], value.counts()[1], value.counts()[2],
          value.counts()[3], value.bounds()[0].equals(Instant.MAX) ? null : value.bounds()[0], value.bounds()[1]);
    }).sorted(java.util.Comparator.comparing(BatchSummary::batchId)).toList();
  }

  private boolean changeAvailableInvitation(final String code, final String update,
      final Map<String, AttributeValue> values, final Map<String, String> names) {
    try {
      final var allValues = new java.util.HashMap<>(values);
      allValues.put(":available", s(AVAILABLE));
      final var allNames = new java.util.HashMap<>(names);
      allNames.put("#state", STATE);
      dynamoDbClient.updateItem(UpdateItemRequest.builder().tableName(table).key(Map.of(KEY, s(storageKey(code))))
          .conditionExpression("#state = :available").updateExpression(update)
          .expressionAttributeNames(allNames).expressionAttributeValues(allValues).build());
      return true;
    } catch (final ConditionalCheckFailedException ignored) {
      return false;
    }
  }

  private Map<String, AttributeValue> get(final String key) {
    return dynamoDbClient.getItem(GetItemRequest.builder().tableName(table).key(Map.of(KEY, s(key)))
        .consistentRead(true).build()).item();
  }

  private String storageKey(final String code) {
    final String normalized = Objects.requireNonNull(code).trim();
    if (normalized.length() < 16 || normalized.length() > 128) {
      return "invitation:invalid";
    }
    return "invitation:" + Base64.getUrlEncoder().withoutPadding()
        .encodeToString(hmac("invitation-code", normalized.getBytes(StandardCharsets.UTF_8)));
  }

  private byte[] hmac(final String domain, final byte[] input) {
    try {
      final Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
      mac.update(domain.getBytes(StandardCharsets.UTF_8));
      mac.update((byte) 0);
      return mac.doFinal(input);
    } catch (final GeneralSecurityException e) {
      throw new AssertionError(e);
    }
  }

  private static String string(final Map<String, AttributeValue> item, final String key) {
    return item == null || item.get(key) == null ? null : item.get(key).s();
  }

  private static byte[] bytes(final Map<String, AttributeValue> item, final String key) {
    return item == null || item.get(key) == null ? null : item.get(key).b().asByteArray();
  }

  private static boolean constantTimeEquals(final byte[] first, final byte[] second) {
    if (first == null || second == null) return false;
    return java.security.MessageDigest.isEqual(first, second);
  }

  public static class InvitationUnavailableException extends Exception {}
}
