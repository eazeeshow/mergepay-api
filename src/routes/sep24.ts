/**
 * SEP-24 anchor callback endpoint.
 *
 * Registered outside the authenticated route scopes: an anchor has no Mergepay
 * session and never will. Its credential is the JWT it signs with its SEP-10
 * key, verified in src/services/sep24-anchor-token.ts against the key
 * published in that anchor's own stellar.toml.
 *
 * This is not the only SEP-24 callback surface. `POST /api/webhooks/sep24`
 * (src/routes/webhooks.ts) accepts the same events from anchors that
 * authenticate with a pre-shared HMAC secret rather than a SEP-10 JWT. The
 * two exist side by side because anchors differ in which scheme they support;
 * each verifies its own credential and both converge on session state.
 */
import type { FastifyInstance } from "fastify";
import { config } from "../config";
import { prisma } from "../db";
import { Errors } from "../errors";
import { requireUser } from "../plugins/auth";
import { anchorService } from "../services/anchor";
import { auditTx } from "../services/audit";
import { serializeAnchorSession } from "../serializers";
import { validateAsset } from "../services/assets";
import { getStatusHistory } from "../services/status-history";
import { toSep24TransactionView } from "../services/sep24-status";
import { rateLimited } from "../lib/rate-limit";
import { openApiBody } from "../lib/openapi";
import {
  applySep24Callback,
  sep24CallbackSchema,
  verifyAnchorToken,
} from "../services/sep24-anchor-token";
import {
  sep24CallbackQuerySchema,
  sep24DepositRequestSchema,
  sep24InitQuerySchema,
  sep24TransactionQuerySchema,
  sep24WithdrawRequestSchema,
} from "../validations/sep24";
import {
  validateSep24Deposit,
  validateSep24Withdraw,
} from "../schemas/sep24";

export default async function sep24Routes(app: FastifyInstance) {
  const initLimit = rateLimited("anchorInit");
  const pollLimit = rateLimited("anchorPoll");

  async function handleStartInteractive(
    kind: "deposit" | "withdrawal",
    req: any,
    requestSchema = kind === "deposit"
      ? sep24DepositRequestSchema
      : sep24WithdrawRequestSchema
  ) {
    const auth = requireUser(req);
    // Query first, then body: both are Zod-owned, and both run before the
    // anchor is contacted, so a malformed request never reaches an upstream
    // call, the database, or the audit log.
    sep24InitQuerySchema.parse(req.query ?? {});
    const body = requestSchema.parse(req.body);

    // The issuer is part of the request contract, so it is validated *with*
    // the code rather than dropped: a caller naming an issuer Mergepay does not
    // issue that asset under would otherwise get a session created against a
    // different asset than the one it asked for.
    validateAsset(body.assetCode, body.assetIssuer);

    const t = await anchorService.getToml(config.ANCHOR_HOME_DOMAIN);
    const challenge = await anchorService.getChallenge(
      t.webAuthEndpoint,
      auth.stellarPublicKey
    );

    const session = await prisma.$transaction(async (tx) => {
      const created = await tx.anchorSession.create({
        data: {
          userId: auth.id,
          anchorName: body.anchorName ?? config.ANCHOR_NAME,
          kind,
          assetCode: body.assetCode,
          status: "incomplete",
        },
      });
      await auditTx(tx, {
        userId: auth.id,
        action: "anchor_session.start",
        entityType: "anchor_session",
        entityId: created.id,
        metadata: { kind, assetCode: body.assetCode },
      });
      return created;
    });

    return {
      session: serializeAnchorSession(session),
      challenge,
    };
  }

  app.post(
    "/api/sep24/deposit",
    {
      preHandler: [app.authenticate, validateSep24Deposit],
      ...initLimit,
      schema: {
        tags: ["SEP-24"],
        summary: "Initiate SEP-24 deposit flow with Zod validation",
        description:
          "Validates payload with Zod and initiates a SEP-24 deposit interactive session.",
        // Documented from the same Zod schema the handler parses with, but with
        // the rules stripped: the handler is the only validator, so a rejection
        // arrives in the documented VALIDATION_ERROR envelope with `issues`.
        querystring: openApiBody(sep24InitQuerySchema, { enforce: false }),
        body: openApiBody(sep24DepositRequestSchema, { enforce: false }),
        response: {
          200: {
            type: "object",
            additionalProperties: true,
            properties: {
              session: { type: "object", additionalProperties: true },
              challenge: { type: "object", additionalProperties: true },
            },
          },
        },
      },
    },
    (req) => handleStartInteractive("deposit", req)
  );

  app.post(
    "/api/sep24/withdraw",
    {
      preHandler: [app.authenticate, validateSep24Withdraw],
      ...initLimit,
      schema: {
        tags: ["SEP-24"],
        summary: "Initiate SEP-24 withdrawal flow with Zod validation",
        description:
          "Validates payload with Zod and initiates a SEP-24 withdrawal interactive session.",
        querystring: openApiBody(sep24InitQuerySchema, { enforce: false }),
        body: openApiBody(sep24WithdrawRequestSchema, { enforce: false }),
        response: {
          200: {
            type: "object",
            additionalProperties: true,
            properties: {
              session: { type: "object", additionalProperties: true },
              challenge: { type: "object", additionalProperties: true },
            },
          },
        },
      },
    },
    (req) => handleStartInteractive("withdrawal", req)
  );

  // SEP-24 status polling (#651).
  //
  // The session row is the source of truth, and it is kept current by the
  // worker's anchor polling (src/worker/index.ts). Answering from the database
  // rather than by calling the anchor here is deliberate: a client polling this
  // route in a loop must not be able to amplify one request per user into one
  // request per poll against the anchor, which is the failure mode the
  // `anchorInit` budget exists to prevent.
  //
  // The response is the SEP-24 transaction object itself, not Mergepay's
  // session envelope, because this is the endpoint a SEP-24-aware client
  // expects. Fields the spec marks optional and Mergepay does not track
  // (`status_eta`, `amount_in`, `fee_details`, …) are omitted rather than
  // invented; `session_id` and `status_history` are Mergepay's own additions.
  app.get(
    "/api/sep24/transaction",
    {
      preHandler: [app.authenticate],
      ...pollLimit,
      schema: {
        tags: ["SEP-24"],
        summary: "Poll SEP-24 transaction status",
        description:
          "Returns the SEP-24 transaction object for one deposit or withdrawal, including Mergepay's status timeline.",
        // Documented but not compiler-enforced: the handler is the only
        // validator, so a rejection arrives in the VALIDATION_ERROR envelope
        // with `issues` naming the field.
        querystring: openApiBody(sep24TransactionQuerySchema, { enforce: false }),
        response: {
          200: {
            type: "object",
            // Locked, not open: this is a published spec shape, so a field
            // added to the view without being declared here is a contract
            // change that has to be made deliberately.
            additionalProperties: false,
            required: [
              "id",
              "kind",
              "status",
              "session_id",
              "started_at",
              "status_history",
            ],
            properties: {
              id: { type: "string" },
              kind: { type: "string", enum: ["deposit", "withdrawal"] },
              status: { type: "string" },
              session_id: { type: "string" },
              more_info_url: { type: "string" },
              started_at: { type: "string" },
              updated_at: { type: "string" },
              completed_at: { type: "string" },
              message: { type: "string" },
              status_history: {
                type: "array",
                items: {
                  type: "object",
                  required: ["status", "at", "source", "reason"],
                  additionalProperties: false,
                  properties: {
                    status: { type: "string" },
                    at: { type: "string" },
                    source: { type: ["string", "null"] },
                    reason: { type: ["string", "null"] },
                  },
                },
              },
            },
          },
        },
      },
    },
    async (req) => {
      const auth = requireUser(req);
      const { id } = sep24TransactionQuerySchema.parse(req.query ?? {});

      // Scoped to the caller, so another user's transaction is a 404 rather
      // than a 403: a status poll must not confirm that an id exists
      // somewhere else in the system.
      const session = await prisma.anchorSession.findFirst({
        where: { userId: auth.id, OR: [{ id }, { externalTransactionId: id }] },
      });
      if (!session) throw Errors.notFound("Transaction not found");

      const history = await getStatusHistory({
        entityType: "anchor_session",
        entityId: session.id,
      });

      return toSep24TransactionView(session, history);
    }
  );
  // Rate limiting here is abuse protection for an endpoint that is
  // unauthenticated until the token is checked. It never substitutes for that
  // check, which remains the authorization gate. Keyed by IP because there is
  // no authenticated user to key by.
  app.post(
    "/api/sep24/callback",
    {
      ...rateLimited("sep24Callback"),
      schema: {
        tags: ["SEP-24"],
        summary: "Process SEP-24 anchor callback",
        description:
          "Accepts and processes SEP-24 transaction status callbacks signed with the anchor SEP-10 JWT token.",
        querystring: openApiBody(sep24CallbackQuerySchema),
        body: openApiBody(sep24CallbackSchema),
        response: {
          200: {
            type: "object",
            additionalProperties: true,
            properties: {
              received: { type: "boolean" },
              status: { type: "string" },
              matched: { type: "integer" },
              updated: { type: "integer" },
            },
          },
        },
      },
    },
    async (req, reply) => {
      // Verified before the body is parsed, so an unauthenticated caller never
      // reaches the schema, the database, or the audit log.
      await verifyAnchorToken(req.headers.authorization);

      sep24CallbackQuerySchema.parse(req.query ?? {});

      const callback = sep24CallbackSchema.parse(req.body ?? {});
      const result = await applySep24Callback(callback);

      // 200 even when no session matched or the transition was disallowed.
      // Anchors retry non-2xx responses, so returning an error for a callback
      // that was correctly processed as a no-op only amplifies load.
      return reply.code(200).send({
        received: true,
        status: result.status,
        matched: result.matched,
        updated: result.updated,
      });
    }
  );
}
