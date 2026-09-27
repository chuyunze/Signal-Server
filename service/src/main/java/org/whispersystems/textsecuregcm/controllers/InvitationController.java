/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.controllers;

import io.dropwizard.auth.Auth;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Optional;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.limits.RateLimitedByIp;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.storage.InvitationsManager;

@Path("/v1/invitations")
@Produces(MediaType.APPLICATION_JSON)
public class InvitationController {
  private static final String UNAVAILABLE = "invitation unavailable";
  private final InvitationsManager invitationsManager;
  private final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager;

  public InvitationController(final InvitationsManager invitationsManager,
      final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager) {
    this.invitationsManager = invitationsManager;
    this.dynamicConfigurationManager = dynamicConfigurationManager;
  }

  public record ClaimRequest(@NotBlank String invitationCode, @NotNull byte[] receiptCredentialRequest) {}
  public record ClaimResponse(byte[] receiptCredentialResponse) {}

  @POST
  @Path("/claim")
  @Consumes(MediaType.APPLICATION_JSON)
  @RateLimitedByIp(RateLimiters.For.INVITATION_CLAIM)
  public ClaimResponse claim(@Auth final Optional<AuthenticatedDevice> authenticatedDevice,
      @NotNull @Valid final ClaimRequest request) {
    if (!dynamicConfigurationManager.getConfiguration().getNumberlessRegistrationConfiguration().enabled()) {
      throw new BadRequestException(UNAVAILABLE);
    }
    if (authenticatedDevice.isPresent()) {
      throw new ForbiddenException();
    }
    try {
      return new ClaimResponse(invitationsManager.claim(request.invitationCode(), request.receiptCredentialRequest()));
    } catch (final InvitationsManager.InvitationUnavailableException | InvalidInputException |
        VerificationFailedException ignored) {
      // Deliberately do not reveal whether the code exists, expired, or was already claimed.
      throw new BadRequestException(UNAVAILABLE);
    }
  }
}
