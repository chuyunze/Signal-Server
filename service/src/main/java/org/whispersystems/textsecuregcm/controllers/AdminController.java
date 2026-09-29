/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.controllers;

import com.google.common.net.HttpHeaders;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.whispersystems.textsecuregcm.auth.AdminAuthorizer;
import org.whispersystems.textsecuregcm.auth.AdminAuthorizer.Principal;
import org.whispersystems.textsecuregcm.auth.AdminAuthorizer.Role;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountStatus;
import org.whispersystems.textsecuregcm.storage.AccountStatusManager;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.AdminAuditManager;
import org.whispersystems.textsecuregcm.storage.InvitationsManager;

@Path("/v1/admin")
@Produces(MediaType.APPLICATION_JSON)
public class AdminController {
  private final AdminAuthorizer authorizer;
  private final AccountsManager accountsManager;
  private final AccountStatusManager accountStatusManager;
  private final InvitationsManager invitationsManager;
  private final AdminAuditManager auditManager;
  private final Clock clock;

  public record AccountSummary(UUID accountId, boolean usernameConfigured, AccountStatus status, long statusVersion,
                               Instant statusUpdatedAt, int deviceCount, Instant registeredAt, Instant lastActiveAt) {}
  public record AccountPage(List<AccountSummary> accounts, String nextCursor) {}
  public record StatusRequest(@NotNull AccountStatus status, @NotBlank String reason) {}
  public record ReasonRequest(@NotBlank String reason) {}
  public record CreateBatchRequest(@NotBlank String batchId, @Min(1) @Max(10_000) int count,
                                   @Min(1) @Max(365) int validDays) {}
  public record InvitationCodeRequest(@NotBlank String invitationCode, @NotBlank String reason) {}
  public record ExtendInvitationRequest(@NotBlank String invitationCode, @Min(1) @Max(365) int validDays,
                                        @NotBlank String reason) {}

  public AdminController(final AdminAuthorizer authorizer, final AccountsManager accountsManager,
      final InvitationsManager invitationsManager, final AdminAuditManager auditManager, final Clock clock) {
    this.authorizer = authorizer;
    this.accountsManager = accountsManager;
    this.accountStatusManager = new AccountStatusManager(accountsManager, clock);
    this.invitationsManager = invitationsManager;
    this.auditManager = auditManager;
    this.clock = clock;
  }

  @GET
  @Path("/me")
  public Principal me(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization) {
    return authorizer.authenticate(authorization);
  }

  @GET
  @Path("/accounts/{accountId}")
  public AccountSummary getAccount(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @PathParam("accountId") final UUID accountId) {
    final Principal principal = authorizer.authenticate(authorization);
    principal.require(Role.ACCOUNT_OPERATOR);
    return summarize(accountsManager.getByAccountIdentifier(accountId).orElseThrow(NotFoundException::new));
  }

  @GET
  @Path("/accounts")
  public AccountPage listAccounts(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @QueryParam("cursor") final String cursor, @QueryParam("limit") final Integer limit) {
    final Principal principal = authorizer.authenticate(authorization);
    principal.require(Role.ACCOUNT_OPERATOR);
    final int pageSize = limit == null ? 50 : limit;
    if (pageSize < 1 || pageSize > 100) throw new BadRequestException("limit must be between 1 and 100");
    final UUID parsedCursor;
    try {
      parsedCursor = cursor == null || cursor.isBlank() ? null : UUID.fromString(cursor);
    } catch (final IllegalArgumentException e) {
      throw new BadRequestException("invalid account cursor");
    }
    final AccountsManager.AccountPage page = accountsManager.listAccounts(pageSize, parsedCursor);
    return new AccountPage(page.accounts().stream().map(AdminController::summarize).toList(),
        page.nextCursor() == null ? null : page.nextCursor().toString());
  }

  @POST
  @Path("/accounts/{accountId}/status")
  @Consumes(MediaType.APPLICATION_JSON)
  public AccountSummary setStatus(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @HeaderParam("X-Admin-Confirmation") final String confirmation,
      @PathParam("accountId") final UUID accountId, @NotNull @Valid final StatusRequest request) {
    final Principal principal = highRisk(authorization, Role.ACCOUNT_OPERATOR, confirmation, request.status().name());
    if (request.status() == AccountStatus.PURGED) throw new BadRequestException("PURGED requires deletion workflow");
    final Account before = accountsManager.getByAccountIdentifier(accountId).orElseThrow(NotFoundException::new);
    final AccountStatus beforeStatus = before.getAccountStatus();
    final Account updated = accountStatusManager.transition(accountId, request.status(), principal.subject(),
        request.reason());
    auditManager.append(principal.subject(), "ACCOUNT_STATUS_CHANGED", accountId.toString(),
        beforeStatus.name(), updated.getAccountStatus().name(), request.reason());
    return summarize(updated);
  }

  @POST
  @Path("/accounts/{accountId}/disconnect")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response disconnect(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @HeaderParam("X-Admin-Confirmation") final String confirmation,
      @PathParam("accountId") final UUID accountId, @NotNull @Valid final ReasonRequest request) {
    final Principal principal = highRisk(authorization, Role.ACCOUNT_OPERATOR, confirmation, "DISCONNECT");
    final Account account = accountsManager.getByAccountIdentifier(accountId).orElseThrow(NotFoundException::new);
    accountsManager.disconnectAllDevices(account);
    auditManager.append(principal.subject(), "ACCOUNT_DEVICES_DISCONNECTED", accountId.toString(), "", "",
        request.reason());
    return Response.noContent().build();
  }

  @DELETE
  @Path("/accounts/{accountId}")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response deleteAccount(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @HeaderParam("X-Admin-Confirmation") final String confirmation,
      @PathParam("accountId") final UUID accountId, @NotNull @Valid final ReasonRequest request) {
    final Principal principal = highRisk(authorization, Role.SUPER_ADMIN, confirmation, accountId.toString());
    final Account account = accountsManager.getByAccountIdentifier(accountId).orElseThrow(NotFoundException::new);
    final String before = "status=" + account.getAccountStatus().name() + "; devices=" + account.getDevices().size();

    accountsManager.delete(accountId, AccountsManager.DeletionReason.ADMIN_DELETED);
    auditManager.append(principal.subject(), "ACCOUNT_DELETED", accountId.toString(), before, "DELETED",
        request.reason());

    return Response.noContent().build();
  }

  @GET
  @Path("/invitations/batches")
  public List<InvitationsManager.BatchSummary> listBatches(
      @HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization) {
    authorizer.authenticate(authorization).require(Role.INVITATION_OPERATOR);
    return invitationsManager.listBatches();
  }

  @POST
  @Path("/invitations/batches")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response createBatch(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @HeaderParam("X-Admin-Confirmation") final String confirmation,
      @NotNull @Valid final CreateBatchRequest request) {
    final Principal principal = highRisk(authorization, Role.INVITATION_OPERATOR, confirmation, request.batchId());
    final List<String> codes = invitationsManager.createBatch(request.batchId(), request.count(),
        clock.instant().plus(Duration.ofDays(request.validDays())));
    auditManager.append(principal.subject(), "INVITATION_BATCH_CREATED", request.batchId(), "",
        String.valueOf(codes.size()), "validDays=" + request.validDays());
    return Response.ok(codes).header(HttpHeaders.CACHE_CONTROL, "no-store, max-age=0")
        .header("Pragma", "no-cache").build();
  }

  @DELETE
  @Path("/invitations/batches/{batchId}")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response deleteBatch(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @HeaderParam("X-Admin-Confirmation") final String confirmation,
      @PathParam("batchId") final String batchId, @NotNull @Valid final ReasonRequest request) {
    final Principal principal = highRisk(authorization, Role.INVITATION_OPERATOR, confirmation, batchId);
    final InvitationsManager.DeleteBatchResult result = invitationsManager.deleteBatch(batchId);
    if (result.invitations() == 0) throw new NotFoundException("invitation batch not found");
    auditManager.append(principal.subject(), "INVITATION_BATCH_DELETED", batchId,
        "invitations=" + result.invitations(), "hidden; revoked=" + result.revoked(), request.reason());
    return Response.noContent().build();
  }

  @POST
  @Path("/invitations/revoke")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response revokeInvitation(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @HeaderParam("X-Admin-Confirmation") final String confirmation,
      @NotNull @Valid final InvitationCodeRequest request) {
    final Principal principal = highRisk(authorization, Role.INVITATION_OPERATOR, confirmation, "REVOKE");
    if (!invitationsManager.revoke(request.invitationCode())) {
      throw new BadRequestException("invitation is not available");
    }
    auditManager.append(principal.subject(), "INVITATION_REVOKED", "redacted-code", "AVAILABLE", "REVOKED",
        request.reason());
    return Response.noContent().build();
  }

  @POST
  @Path("/invitations/extend")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response extendInvitation(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @HeaderParam("X-Admin-Confirmation") final String confirmation,
      @NotNull @Valid final ExtendInvitationRequest request) {
    final Principal principal = highRisk(authorization, Role.INVITATION_OPERATOR, confirmation, "EXTEND");
    if (!invitationsManager.extend(request.invitationCode(),
        clock.instant().plus(Duration.ofDays(request.validDays())))) {
      throw new BadRequestException("invitation is not available");
    }
    auditManager.append(principal.subject(), "INVITATION_EXTENDED", "redacted-code", "", "",
        request.reason() + "; validDays=" + request.validDays());
    return Response.noContent().build();
  }

  @GET
  @Path("/audit")
  public List<AdminAuditManager.Event> audit(@HeaderParam(HttpHeaders.AUTHORIZATION) final String authorization,
      @QueryParam("limit") final Integer limit) {
    authorizer.authenticate(authorization).require(Role.AUDITOR);
    return auditManager.recent(limit == null ? 100 : limit);
  }

  private Principal highRisk(final String authorization, final Role role,
      final String confirmation, final String expectedConfirmation) {
    final Principal principal = authorizer.authenticate(authorization);
    principal.require(role);
    principal.requireRecentMfa();
    if (!expectedConfirmation.equals(confirmation)) throw new BadRequestException("confirmation mismatch");
    return principal;
  }

  private static AccountSummary summarize(final Account account) {
    return new AccountSummary(account.getAccountIdentifier(), account.getUsernameHash().isPresent(),
        account.getAccountStatus(), account.getAccountStatusVersion(),
        account.getAccountStatusUpdatedAt().orElse(null), account.getDevices().size(),
        Instant.ofEpochMilli(account.getPrimaryDevice().getCreated()),
        Instant.ofEpochMilli(account.getPrimaryDevice().getLastSeen()));
  }
}
