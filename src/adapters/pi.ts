import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { AutoClassifier } from "../index.js";
import { log } from "../log.js";
import { VERSION } from "../version.js";
import type { DecisionOutcome } from "../types.js";

/**
 * The pi adapter — the classifier as an `authorizerChain` link of
 * `@gotgenes/pi-permission-system`.
 *
 * The permission system's rule list runs first: an `allow` runs, a `deny`
 * blocks, and every `ask` the list cannot decide is handed to the authorizer
 * chain, where this extension judges it. `allow`/`deny` settle the ask without
 * a human; only what this extension defers reaches the operator's prompt.
 *
 * The permission system is imported dynamically, so this file builds and loads
 * without it; a missing install degrades to one logged warning and an inert
 * extension (pi's own defaults apply), never a load failure.
 */

const PERMISSION_SYSTEM = "@gotgenes/pi-permission-system";
const DEFAULT_LINK_NAME = "auto-classifier";

/**
 * The entry file of the permission system as installed under pi's npm
 * directory (`<agent dir>/npm/node_modules`), or null. pi loads extensions
 * through jiti with no shared node_modules, so a bare import from this file
 * does not always resolve; this is the deterministic fallback. The agent dir
 * honors pi's own `PI_CODING_AGENT_DIR` override.
 */
function permissionSystemEntry(): string | null {
  const envDir = process.env.PI_CODING_AGENT_DIR?.trim();
  const agentDir = envDir
    ? envDir === "~" || envDir.startsWith("~/")
      ? path.join(os.homedir(), envDir.slice(1))
      : envDir
    : path.join(os.homedir(), ".pi", "agent");
  const pkgDir = path.join(agentDir, "npm", "node_modules", PERMISSION_SYSTEM);
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as {
      exports?: unknown;
      main?: string;
    };
    let entry: unknown = pkg.exports;
    if (entry && typeof entry === "object") entry = (entry as Record<string, unknown>)["."];
    if (entry && typeof entry === "object") entry = (entry as Record<string, unknown>)["default"];
    entry = entry ?? pkg.main;
    if (typeof entry !== "string") return null;
    return path.join(pkgDir, entry);
  } catch {
    return null;
  }
}

/** The module surface this adapter needs from the permission system. */
interface PermissionSystemModule {
  getPermissionsService?: (sessionId: string) => PermissionService | undefined;
}

/** Load the permission system: bare import first, then pi's npm directory. */
async function loadPermissionSystem(): Promise<PermissionSystemModule | undefined> {
  try {
    // Non-literal specifier: bundlers leave the import to runtime
    // resolution, so a build of this file never needs the package.
    const specifier = PERMISSION_SYSTEM;
    return (await import(specifier)) as PermissionSystemModule;
  } catch {
    const entry = permissionSystemEntry();
    if (!entry) return undefined;
    try {
      return (await import(pathToFileURL(entry).href)) as PermissionSystemModule;
    } catch (err) {
      log(`failed to load ${PERMISSION_SYSTEM} from ${entry}: ${err instanceof Error ? err.message : String(err)}`);
      return undefined;
    }
  }
}

/** The pi event-bus surface, all this adapter needs. */
interface PiEvents {
  on(channel: string, handler: (data: unknown) => void): () => void;
}
interface PiExtensionApi {
  events?: PiEvents;
  [key: string]: unknown;
}

/** Payload of the `permissions:ready` broadcast; read defensively. */
interface ReadyEvent {
  sessionId?: string | null;
  adjudicatesLocally?: boolean;
}

/**
 * The subset of the permission system's `PromptPermissionDetails` this
 * adapter reads: the command a bash ask is about, and the ids a telemetry row
 * wants.
 */
interface AskDetails {
  requestId?: string;
  toolName?: string;
  toolCallId?: string;
  command?: string;
  [key: string]: unknown;
}

/** The permission system's `AuthorizerVerdict`. */
type Verdict = { kind: "allow" } | { kind: "deny"; reason?: string } | { kind: "defer" };

/** The narrow review-log seam the chain injects at authorize time. */
interface AuthorizerLog {
  review(event: string, details?: Record<string, unknown>): void;
  debug(event: string, details?: Record<string, unknown>): void;
}

interface PermissionService {
  registerAuthorizer(
    name: string,
    authorize: (details: AskDetails, query: unknown, record: AuthorizerLog) => Promise<Verdict>
  ): () => void;
  [key: string]: unknown;
}

export interface PiAdapterOptions {
  /** Name to register under; the operator must put it in `authorizerChain`. */
  linkName?: string;
  /**
   * How the permission system module is loaded. Production uses the default
   * (bare import, then pi's npm directory); tests inject a fake so they never
   * depend on module-mock behavior.
   */
  importPermissionSystem?: () => Promise<PermissionSystemModule | undefined>;
}

export function createPiExtension(customClassifier?: AutoClassifier, options: PiAdapterOptions = {}) {
  const linkName = options.linkName ?? DEFAULT_LINK_NAME;
  const loadModule = options.importPermissionSystem ?? loadPermissionSystem;
  // Built lazily so importing this module never reads config or touches the
  // state directory until the permission system's first ask reaches us.
  let classifier: AutoClassifier | undefined = customClassifier;
  const getClassifier = (): AutoClassifier => (classifier ??= new AutoClassifier());
  const registered = new Set<string>();
  let warnedNoPermissionSystem = false;

  const warnNoPermissionSystem = () => {
    if (warnedNoPermissionSystem) return;
    warnedNoPermissionSystem = true;
    const msg =
      `no ${PERMISSION_SYSTEM} node answered for this session. The classifier has nothing to ` +
      `hook into and stays inert (pi's own defaults apply). Install the permission system ` +
      `and restart pi.`;
    log(`WARNING: ${msg}`);
    console.error(`[auto-classifier] ${msg}`);
  };

  return function constructAutoClassifierPi(pi: PiExtensionApi) {
    if (!pi?.events?.on) {
      log(`WARNING: no pi events surface found; the pi adapter is inactive (v${VERSION})`);
      return;
    }

    pi.events.on("permissions:ready", (data: unknown) => {
      void (async () => {
        const evt = (data ?? {}) as ReadyEvent;
        const sessionId = typeof evt.sessionId === "string" && evt.sessionId ? evt.sessionId : null;
        if (!sessionId) return; // the node published no keyed service
        if (registered.has(sessionId)) return; // ready fires at least twice per session

        let service: PermissionService | undefined;
        try {
          const mod = await loadModule();
          service = mod?.getPermissionsService?.(sessionId);
        } catch {
          warnNoPermissionSystem();
          return;
        }
        if (!service?.registerAuthorizer) {
          warnNoPermissionSystem();
          return;
        }

        const authorize = async (details: AskDetails, _query: unknown, record: AuthorizerLog): Promise<Verdict> => {
          const command = typeof details?.command === "string" ? details.command : "";
          if (!command.trim()) {
            // Not a command ask (a path, skill, ...): the rule list and the
            // operator decide it; the classifier judges commands.
            return { kind: "defer" };
          }

          let outcome: DecisionOutcome;
          try {
            outcome = await getClassifier().evaluate(command, sessionId, undefined, {
              callId: details.toolCallId,
            });
          } catch (err) {
            // A classifier that cannot decide must never consent: defer, so a
            // human decides, and say so in the log.
            log(`error judging "${command.slice(0, 120)}": ${err instanceof Error ? err.message : String(err)} -- deferring`);
            record?.debug?.("auto-classifier:error", { command: command.slice(0, 500) });
            return { kind: "defer" };
          }

          log(
            `${outcome.decision} "${command.slice(0, 120).replace(/\n/g, " ")}"${
              outcome.decision === "allow" ? "" : ` -- ${(outcome.reason ?? "").slice(0, 160)}`
            }`
          );

          if (outcome.decision === "allow") {
            record?.review?.("auto-classifier:allow", { command: command.slice(0, 500) });
            return { kind: "allow" };
          }
          if (outcome.decision === "deny") {
            // The reason is the teaching text the invoking model sees.
            return { kind: "deny", reason: outcome.reason };
          }
          // `ask` and `force_ask` (a repeated denial that reached the
          // escalation threshold): the operator's prompt is exactly where this
          // belongs. Leave a trail so the prompt's history shows the finding.
          record?.review?.("auto-classifier:escalation", {
            command: command.slice(0, 500),
            finding: (outcome.reason ?? "").slice(0, 500),
            consecutiveCount: outcome.consecutiveCount,
          });
          return { kind: "defer" };
        };

        try {
          // The returned disposer runs when the permission system tears the
          // service down at session_shutdown; a restarted session fires
          // permissions:ready again and re-registers.
          service.registerAuthorizer(linkName, authorize);
          registered.add(sessionId);
          log(`registered authorizer "${linkName}" for session ${sessionId} (v${VERSION})`);
        } catch (err) {
          log(`failed to register authorizer "${linkName}": ${err instanceof Error ? err.message : String(err)}`);
        }
      })();
    });
  };
}

export default createPiExtension();
