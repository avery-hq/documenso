/**
 * Machine-to-machine tenant provisioning endpoint (AveryIQ fork addition).
 *
 * Documenso ships no public/Bearer API for creating Organisations, Teams, API
 * tokens, or webhooks — those operations only exist as session-authenticated
 * tRPC or direct server-only function calls. AveryIQ provisions one Documenso
 * Organisation + Team (with its own scoped API token + webhook) per customer
 * organisation, so we expose a single authenticated endpoint that drives the
 * existing server-only functions in one request.
 *
 * Auth is a shared secret (NEXT_PRIVATE_PROVISIONING_SECRET) presented as a
 * Bearer token — this is a trusted backend-to-backend call, not an end-user or
 * public-API surface. All created resources are owned by a designated service
 * ADMIN user (NEXT_PRIVATE_PROVISIONING_OWNER_EMAIL); isolation between tenants
 * is enforced at the Team level (tokens, webhooks, and documents are all
 * team-scoped), so a shared owner does not leak data across tenants.
 *
 * This file is published under the project's AGPL license.
 */

import crypto from 'node:crypto';
import { AppError } from '@documenso/lib/errors/app-error';
import { createOrganisation } from '@documenso/lib/server-only/organisation/create-organisation';
import { createApiToken } from '@documenso/lib/server-only/public-api/create-api-token';
import { getSubscriptionClaim } from '@documenso/lib/server-only/subscription/get-subscription-claim';
import { createTeam } from '@documenso/lib/server-only/team/create-team';
import { getUserByEmail } from '@documenso/lib/server-only/user/get-user-by-email';
import { createWebhook } from '@documenso/lib/server-only/webhooks/create-webhook';
import { INTERNAL_CLAIM_ID } from '@documenso/lib/types/subscription';
import { env } from '@documenso/lib/utils/env';
import { prisma } from '@documenso/prisma';
import { sValidator } from '@hono/standard-validator';
import { OrganisationType, Role } from '@prisma/client';
import { Hono } from 'hono';

import type { HonoEnv } from '../../router';
import {
  DEFAULT_WEBHOOK_EVENTS,
  type ProvisionTenantResponse,
  ZProvisionTenantRequestSchema,
} from './provisioning.types';

/**
 * Constant-time secret comparison. Both inputs are SHA-256 hashed first so the
 * fixed-length compare never leaks the secret's length (timingSafeEqual throws
 * on unequal-length buffers).
 */
function secretsMatch(presented: string, configured: string): boolean {
  const presentedHash = crypto.createHash('sha256').update(presented).digest();
  const configuredHash = crypto.createHash('sha256').update(configured).digest();

  return crypto.timingSafeEqual(presentedHash, configuredHash);
}

function slugify(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40) || 'team'
  );
}

function uniqueTeamUrl(name: string): string {
  return `${slugify(name)}-${crypto.randomUUID().slice(0, 8)}`;
}

function generateWebhookSecret(): string {
  return crypto.randomBytes(32).toString('hex');
}

export const provisioningRoute = new Hono<HonoEnv>().post(
  '/tenant',
  sValidator('json', ZProvisionTenantRequestSchema),
  async (c) => {
    const logger = c.get('logger');

    const configuredSecret = env('NEXT_PRIVATE_PROVISIONING_SECRET');

    // Endpoint is opt-in: without a configured secret it stays disabled.
    if (!configuredSecret) {
      return c.json({ error: 'Provisioning endpoint is not enabled' }, 503);
    }

    const authorizationHeader = c.req.header('authorization') ?? '';
    const [presentedSecret] = authorizationHeader.split('Bearer ').filter((s) => s.length > 0);

    if (!presentedSecret || !secretsMatch(presentedSecret, configuredSecret)) {
      return c.json({ error: 'Unauthorized' }, 401);
    }

    const ownerEmail = env('NEXT_PRIVATE_PROVISIONING_OWNER_EMAIL');

    if (!ownerEmail) {
      return c.json({ error: 'NEXT_PRIVATE_PROVISIONING_OWNER_EMAIL is not configured' }, 500);
    }

    try {
      const body = c.req.valid('json');

      const owner = await getUserByEmail({ email: ownerEmail }).catch(() => null);

      if (!owner) {
        return c.json({ error: 'Provisioning owner user not found' }, 500);
      }

      if (!owner.roles.includes(Role.ADMIN)) {
        return c.json({ error: 'Provisioning owner user must have the ADMIN role' }, 500);
      }

      const teamName = body.teamName ?? body.organisationName;
      const teamUrl = body.teamUrl ?? uniqueTeamUrl(body.organisationName);
      const tokenName = body.tokenName ?? `${body.organisationName} API key`;

      // FREE claim mirrors `admin.organisation.create`; on self-hosted instances
      // (billing disabled) the team-count limit on this claim is not enforced.
      const claim = await getSubscriptionClaim(INTERNAL_CLAIM_ID.FREE);

      const organisation = await createOrganisation({
        userId: owner.id,
        name: body.organisationName,
        type: OrganisationType.ORGANISATION,
        claim,
      });

      // createTeam returns void; the owner (org ADMIN) inherits team admin via
      // internal org groups, so the subsequent token/webhook calls pass their
      // MANAGE_TEAM permission checks.
      await createTeam({
        userId: owner.id,
        teamName,
        teamUrl,
        organisationId: organisation.id,
        inheritMembers: true,
      });

      const team = await prisma.team.findFirstOrThrow({
        where: { url: teamUrl, organisationId: organisation.id },
        select: { id: true },
      });

      let webhookId: string | null = null;
      let webhookSecret: string | null = null;

      if (body.webhookUrl) {
        webhookSecret = generateWebhookSecret();

        const webhook = await createWebhook({
          webhookUrl: body.webhookUrl,
          eventTriggers: body.webhookEvents ?? DEFAULT_WEBHOOK_EVENTS,
          secret: webhookSecret,
          enabled: true,
          userId: owner.id,
          teamId: team.id,
        });

        webhookId = webhook.id;
      }

      // Raw token is returned exactly once here — the DB only stores its hash.
      const { token: apiToken } = await createApiToken({
        userId: owner.id,
        teamId: team.id,
        tokenName,
        expiresIn: null,
      });

      logger.info({
        msg: 'Provisioned Documenso tenant',
        organisationId: organisation.id,
        teamId: team.id,
        teamUrl,
        webhookId,
      });

      return c.json(
        {
          organisationId: organisation.id,
          teamId: team.id,
          teamUrl,
          apiToken,
          webhookId,
          webhookSecret,
        } satisfies ProvisionTenantResponse,
        201,
      );
    } catch (error) {
      logger.error(error);

      if (error instanceof AppError) {
        const { status, body } = AppError.toRestAPIError(error);

        return c.json({ error: body.message, code: error.code }, status);
      }

      return c.json({ error: 'Internal server error' }, 500);
    }
  },
);
