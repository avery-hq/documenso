import { WebhookTriggerEvents } from '@prisma/client';
import { z } from 'zod';

/**
 * Default set of webhook events a provisioned tenant subscribes to. Mirrors the
 * document lifecycle events the consuming application (AveryIQ) reacts to for
 * lease / renewal signing.
 */
export const DEFAULT_WEBHOOK_EVENTS: WebhookTriggerEvents[] = [
  WebhookTriggerEvents.DOCUMENT_CREATED,
  WebhookTriggerEvents.DOCUMENT_SENT,
  WebhookTriggerEvents.DOCUMENT_OPENED,
  WebhookTriggerEvents.DOCUMENT_SIGNED,
  WebhookTriggerEvents.DOCUMENT_COMPLETED,
  WebhookTriggerEvents.DOCUMENT_REJECTED,
  WebhookTriggerEvents.DOCUMENT_CANCELLED,
];

export const ZProvisionTenantRequestSchema = z.object({
  organisationName: z.string().min(1).max(255),
  teamName: z.string().min(1).max(255).optional(),
  teamUrl: z
    .string()
    .min(1)
    .max(60)
    .regex(/^[a-z0-9-]+$/, 'teamUrl may only contain lowercase letters, numbers and hyphens')
    .optional(),
  tokenName: z.string().min(1).max(255).optional(),
  webhookUrl: z.string().url().optional(),
  webhookEvents: z.array(z.nativeEnum(WebhookTriggerEvents)).nonempty().optional(),
});

export type ProvisionTenantRequest = z.infer<typeof ZProvisionTenantRequestSchema>;

export const ZProvisionTenantResponseSchema = z.object({
  organisationId: z.string(),
  teamId: z.number(),
  teamUrl: z.string(),
  apiToken: z.string(),
  webhookId: z.string().nullable(),
  webhookSecret: z.string().nullable(),
});

export type ProvisionTenantResponse = z.infer<typeof ZProvisionTenantResponseSchema>;
