/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.controllers.RateLimitExceededException;
import org.whispersystems.textsecuregcm.controllers.VerificationSessionRateLimitExceededException;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;

/**
 * 当 RegistrationService gRPC 服务不可用时的 NoOp 实现。
 *
 * <p>所有方法返回默认值,不连接 gRPC 服务器,避免挂起等待超时。
 * 用于自建服务器场景,在没有部署 RegistrationService 时:
 * <ul>
 *   <li>{@code createRegistrationSession} 返回一个未验证的默认 session</li>
 *   <li>{@code sendVerificationCode} 返回已发送状态(实际未发送 SMS)</li>
 *   <li>{@code checkVerificationCode} 返回已验证状态(任意验证码均可通过)</li>
 *   <li>{@code getSession} 返回默认 session 元数据</li>
 * </ul>
 *
 * <p><strong>注意:</strong> 此实现跳过 SMS 验证,任意验证码均可通过。
 * 仅适用于受信任的自建服务器环境。
 */
public class NoOpRegistrationServiceClient extends RegistrationServiceClient {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final long DEFAULT_EXPIRATION_SECONDS = 3600; // 1小时

  /**
   * sessionId(Base64) -> e164 号码。
   * NoOp 实现不持久化 session, 但后续调用 (getSession/sendVerificationCode/checkVerificationCode)
   * 必须返回真实号码, 否则 VerificationController 会用空字符串查询 numbers 表 (P=""),
   * 触发 DynamoDB "key attribute cannot contain an empty string value" 500 错误。
   * 仅存于内存, 服务器重启后丢失, 需要客户端重新发起注册。
   */
  private static final Map<String, String> SESSION_NUMBERS = new ConcurrentHashMap<>();

  /**
   * 已通过验证码校验的 sessionId(Base64)集合。
   * POST /v1/registration 时 PhoneVerificationTokenManager.verifyBySessionId 会通过
   * getSession 检查 session.verified(); 若不记录该状态, 建号请求永远返回 401
   * "registration session is unverified"。
   */
  private static final java.util.Set<String> VERIFIED_SESSIONS = ConcurrentHashMap.newKeySet();

  public NoOpRegistrationServiceClient(final byte[] collationKeySalt) {
    super(collationKeySalt);
  }

  @Override
  public RegistrationServiceSession createRegistrationSession(
      final Phonenumber.PhoneNumber phoneNumber,
      final String sourceHost,
      final boolean accountExistsWithPhoneNumber,
      @Nullable final String clientMcc,
      @Nullable final String clientMnc,
      final Duration timeout) throws RateLimitExceededException {

    final String e164 = PhoneNumberUtil.getInstance().format(phoneNumber,
        PhoneNumberUtil.PhoneNumberFormat.E164);

    final byte[] sessionId = new byte[16];
    RANDOM.nextBytes(sessionId);
    SESSION_NUMBERS.put(Base64.getEncoder().encodeToString(sessionId), e164);

    return buildSession(sessionId, e164, false);
  }

  @Override
  public RegistrationServiceSession sendVerificationCode(final byte[] sessionId,
      final MessageTransport messageTransport,
      final ClientType clientType,
      @Nullable final String acceptLanguage,
      @Nullable final String senderOverride,
      final Duration timeout)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException,
      RegistrationServiceSenderException, RegistrationFraudException {

    // 返回已发送状态(实际未发送 SMS),允许检查验证码
    return buildDefaultSessionFromId(sessionId, false);
  }

  @Override
  public RegistrationServiceSession checkVerificationCode(final byte[] sessionId,
      final String verificationCode,
      final Duration timeout)
      throws VerificationSessionRateLimitExceededException, RegistrationServiceException {

    // 跳过验证码校验,直接返回已验证状态,并记录该 session 已验证
    final String key = Base64.getEncoder().encodeToString(sessionId);
    if (SESSION_NUMBERS.containsKey(key)) {
      VERIFIED_SESSIONS.add(key);
    }
    return buildDefaultSessionFromId(sessionId, true);
  }

  @Override
  public Optional<RegistrationServiceSession> getSession(final byte[] sessionId,
      final Duration timeout) {
    final String key = Base64.getEncoder().encodeToString(sessionId);
    final String e164 = SESSION_NUMBERS.get(key);
    if (e164 == null) {
      // 未知 session(如服务器重启导致内存 map 丢失): 返回 empty → HTTP 404。
      // 客户端 createOrValidateSession 收到 SessionNotFound 后会自动清除旧 session 并重新创建,
      // 从而拿到号码正确的新 session, 避免后续用空号码查询 numbers 表导致 500。
      return Optional.empty();
    }
    // 返回该 session 实际的验证状态; 已通过 checkVerificationCode 的 session 标记为 verified,
    // 否则 POST /v1/registration 会因 session.verified()=false 返回 401。
    return Optional.of(buildSession(sessionId, e164, VERIFIED_SESSIONS.contains(key)));
  }

  /**
   * 构造 RegistrationServiceSession。
   */
  private static RegistrationServiceSession buildSession(final byte[] sessionId,
      final String e164,
      final boolean verified) {
    return new RegistrationServiceSession(
        sessionId,
        e164,
        verified,
        0L,                    // nextSms: 立即可以请求
        null,                  // nextVoiceCall
        null,                  // nextVerificationAttempt
        DEFAULT_EXPIRATION_SECONDS
    );
  }

  /**
   * 从已有的 sessionId 构造默认 session(用于后续操作)。
   * 号码从 SESSION_NUMBERS 中取回; 查不到(如服务器重启)时返回空字符串。
   */
  private static RegistrationServiceSession buildDefaultSessionFromId(final byte[] sessionId,
      final boolean verified) {
    final String e164 = SESSION_NUMBERS.getOrDefault(Base64.getEncoder().encodeToString(sessionId), "");
    return buildSession(sessionId, e164, verified);
  }
}
