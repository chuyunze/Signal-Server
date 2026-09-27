/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.controllers;

import com.google.common.net.HttpHeaders;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.time.Instant;
import java.util.UUID;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.auth.BasicAuthorizationHeader;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountStatus;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;

/** Lets a client with the current high-entropy device credential distinguish a restricted account from bad auth. */
@Path("/v1/accounts/status")
public class AccountStatusController {
  private final AccountsManager accountsManager;

  public AccountStatusController(final AccountsManager accountsManager) {
    this.accountsManager = accountsManager;
  }

  public record AccountStatusResponse(AccountStatus status, long version, @Nullable Instant updatedAt) {}

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Get the authenticated account's administrative access state")
  public AccountStatusResponse getStatus(
      @HeaderParam(HttpHeaders.AUTHORIZATION) final BasicAuthorizationHeader authorizationHeader) {
    if (authorizationHeader == null) {
      throw new NotAuthorizedException("Basic");
    }

    final UUID accountIdentifier;
    try {
      accountIdentifier = UUID.fromString(authorizationHeader.getUsername());
    } catch (final IllegalArgumentException e) {
      throw new NotAuthorizedException("Basic");
    }

    final Account account = accountsManager.getByAccountIdentifier(accountIdentifier)
        .orElseThrow(() -> new NotAuthorizedException("Basic"));
    final Device primaryDevice = account.getDevice(Device.PRIMARY_ID)
        .orElseThrow(() -> new NotAuthorizedException("Basic"));
    if (!primaryDevice.getAuthTokenHash().verify(authorizationHeader.getPassword())) {
      throw new NotAuthorizedException("Basic");
    }

    return new AccountStatusResponse(account.getAccountStatus(), account.getAccountStatusVersion(),
        account.getAccountStatusUpdatedAt().orElse(null));
  }
}
