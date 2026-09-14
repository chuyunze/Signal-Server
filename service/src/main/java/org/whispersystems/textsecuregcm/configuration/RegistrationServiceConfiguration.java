package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import io.dropwizard.core.setup.Environment;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.concurrent.ScheduledExecutorService;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;
import org.whispersystems.textsecuregcm.registration.IdentityTokenCallCredentials;
import org.whispersystems.textsecuregcm.registration.NoOpRegistrationServiceClient;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;

@JsonTypeName("default")
public record RegistrationServiceConfiguration(@NotBlank String host,
                                               int port,
                                               @NotBlank String credentialConfigurationJson,
                                               @NotBlank String identityTokenAudience,
                                               @NotBlank String registrationCaCertificate,
                                               @NotNull SecretBytes collationKeySalt) implements
    RegistrationServiceClientFactory {

  @Override
  public RegistrationServiceClient build(final Environment environment,
      final ScheduledExecutorService identityRefreshExecutor) {

    try {
      final IdentityTokenCallCredentials callCredentials = IdentityTokenCallCredentials.fromCredentialConfig(
          credentialConfigurationJson, identityTokenAudience, identityRefreshExecutor);

      environment.lifecycle().manage(callCredentials);

      return new RegistrationServiceClient(host, port, callCredentials, registrationCaCertificate, collationKeySalt.value());
    } catch (Exception e) {
      // token 初始化失败 (国内连不上 Google API), 不阻塞启动
      // 返回 NoOp 实现:所有方法返回默认值,不连接 gRPC 服务器
      // RegistrationService 不可用, 但文字/群组/音视频聊天不受影响
      System.err.println("WARNING: Failed to initialize RegistrationService credentials: " + e.getMessage()
          + " — using NoOp client (SMS verification will be skipped)");
      return new NoOpRegistrationServiceClient(collationKeySalt.value());
    }
  }
}