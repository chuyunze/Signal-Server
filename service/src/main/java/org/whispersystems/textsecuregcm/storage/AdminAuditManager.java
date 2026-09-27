/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

import static org.whispersystems.textsecuregcm.util.AttributeValues.n;
import static org.whispersystems.textsecuregcm.util.AttributeValues.s;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;

/** Append-only administrative audit events. No mutation or deletion API is exposed. */
public class AdminAuditManager {
  private static final String KEY = "A";
  private static final String PREFIX = "admin-audit:";
  private final String table;
  private final DynamoDbClient dynamoDbClient;
  private final Clock clock;

  public record Event(String id, Instant timestamp, String actor, String action, String target,
                      String before, String after, String reason) {}

  public AdminAuditManager(final String table, final DynamoDbClient dynamoDbClient, final Clock clock) {
    this.table = table;
    this.dynamoDbClient = dynamoDbClient;
    this.clock = clock;
  }

  public Event append(final String actor, final String action, final String target,
      final String before, final String after, final String reason) {
    final Instant now = clock.instant();
    final String id = now.toEpochMilli() + ":" + UUID.randomUUID();
    dynamoDbClient.putItem(PutItemRequest.builder().tableName(table).item(Map.of(
        KEY, s(PREFIX + id), "AT", n(now.getEpochSecond()), "AA", s(clean(actor)),
        "AC", s(clean(action)), "AG", s(clean(target)), "AB", s(clean(before)),
        "AN", s(clean(after)), "AR", s(clean(reason)))).build());
    return new Event(id, now, actor, action, target, before, after, reason);
  }

  public List<Event> recent(final int requestedLimit) {
    final int limit = Math.max(1, Math.min(requestedLimit, 500));
    final List<Event> events = new ArrayList<>();
    dynamoDbClient.scanPaginator(ScanRequest.builder().tableName(table)
        .filterExpression("begins_with(#key, :prefix)")
        .expressionAttributeNames(Map.of("#key", KEY))
        .expressionAttributeValues(Map.of(":prefix", s(PREFIX))).build())
        .items().forEach(item -> events.add(fromItem(item)));
    return events.stream().sorted(Comparator.comparing(Event::timestamp).reversed()).limit(limit).toList();
  }

  private static Event fromItem(final Map<String, AttributeValue> item) {
    return new Event(item.get(KEY).s().substring(PREFIX.length()),
        Instant.ofEpochSecond(Long.parseLong(item.get("AT").n())),
        item.get("AA").s(), item.get("AC").s(), item.get("AG").s(), item.get("AB").s(),
        item.get("AN").s(), item.get("AR").s());
  }

  private static String clean(final String value) {
    final String result = value == null ? "" : value.replaceAll("[\\r\\n\\t]", " ");
    return result.substring(0, Math.min(result.length(), 512));
  }
}
