import { describe, it, expect, beforeEach } from "bun:test";
import { AutoClassifier } from "../src/index.js";
import { StateManager } from "../src/state/state-manager.js";
import { createPiExtension } from "../src/adapters/pi.js";
import { FakeLlm } from "./helpers/fake-llm.js";
import { tmpStateDir } from "./helpers/tmp-state.js";
import { testConfig } from "./helpers/config.js";

/** The permission-system side of the seam, faked. */
interface RegisterRecord {
  name: string;
  authorize: (details: unknown, query: unknown, record: RecordLog) => Promise<{ kind: string; reason?: string }>;
}
interface RecordLog {
  review(event: string, details?: Record<string, unknown>): void;
  debug(event: string, details?: Record<string, unknown>): void;
}

function fakeRecordLog(): RecordLog & { reviews: Array<{ event: string; details?: Record<string, unknown> }> } {
  const reviews: Array<{ event: string; details?: Record<string, unknown> }> = [];
  return {
    reviews,
    review(event, details) {
      reviews.push({ event, details });
    },
    debug() {},
  };
}

/**
 * A pi-shaped host: an events bus whose `on` captures the `permissions:ready`
 * handler so the test can fire it.
 */
function fakePi() {
  let readyHandler: ((data: unknown) => void) | undefined;
  const pi = {
    events: {
      on(channel: string, handler: (data: unknown) => void) {
        if (channel === "permissions:ready") readyHandler = handler;
        return () => {};
      },
    },
  };
  return {
    pi,
    fireReady(sessionId: string | null) {
      expect(readyHandler).toBeDefined();
      readyHandler!({ sessionId, adjudicatesLocally: true });
    },
  };
}

function makeHarness(
  llm: FakeLlm,
  policy: Parameters<typeof testConfig>[0] = {},
  opts: { broken?: boolean } = {},
) {
  const config = testConfig(policy);
  const state = new StateManager(config.policy.slidingWindowMs, config.policy.consecutiveThreshold, tmpStateDir());
  const classifier = new AutoClassifier(config, { classifier: llm, stateManager: state });
  const registered: RegisterRecord[] = [];
  const host = fakePi();
  // The loader is injected instead of module-mocked: bun's `mock.module`
  // interception of a non-literal dynamic import is version-dependent, so the
  // fake must be deterministic on every machine.
  const extension = createPiExtension(classifier, {
    importPermissionSystem: async () =>
      opts.broken
        ? undefined
        : {
            getPermissionsService(sessionId: string) {
              if (!sessionId) return undefined;
              return {
                registerAuthorizer(name: string, authorize: RegisterRecord["authorize"]) {
                  registered.push({ name, authorize });
                  return () => {};
                },
              };
            },
          },
  });

  return { llm, host, registered, extension };
}

beforeEach(() => {
  process.env.AUTO_CLASSIFIER_LOG = ""; // the adapter's file log is irrelevant here
});

/** Fire ready and wait for the async handler (dynamic import + registration). */
async function settle(host: ReturnType<typeof fakePi>, sessionId = "ses_pi_1") {
  host.fireReady(sessionId);
  await new Promise((r) => setTimeout(r, 10));
}

describe("pi adapter", () => {
  it("registers an authorizer named 'auto-classifier' on permissions:ready", async () => {
    const { llm, host, registered, extension } = makeHarness(new FakeLlm());
    extension(host.pi);
    await settle(host);
    expect(registered).toHaveLength(1);
    expect(registered[0]!.name).toBe("auto-classifier");
    void llm;
  });

  it("is idempotent: ready fires twice per session, registration happens once", async () => {
    const { llm, host, registered, extension } = makeHarness(new FakeLlm());
    extension(host.pi);
    await settle(host, "ses_a");
    await settle(host, "ses_a"); // the second fire (first before_agent_start)
    expect(registered).toHaveLength(1);
    void llm;
  });

  it("allows a command the classifier allows, and records the trail", async () => {
    const { host, registered, extension } = makeHarness(new FakeLlm());
    extension(host.pi);
    await settle(host);
    const record = fakeRecordLog();
    const verdict = await registered[0]!.authorize({ command: "git status", toolCallId: "c1" }, undefined, record);
    expect(verdict).toEqual({ kind: "allow" });
    expect(record.reviews.map((r) => r.event)).toContain("auto-classifier:allow");
  });

  it("denies with the classifier's teaching reason", async () => {
    const { host, registered, extension } = makeHarness(new FakeLlm([{ allow: false, reason: "deletes audit logs" }]));
    extension(host.pi);
    await settle(host);
    const verdict = await registered[0]!.authorize({ command: "rm -rf /var/log/audit", toolCallId: "c1" }, undefined, fakeRecordLog());
    expect(verdict.kind).toBe("deny");
    expect(verdict.reason).toMatch(/deletes audit logs/);
  });

  it("defers an escalation (force_ask) to the operator's prompt and records the finding", async () => {
    const { host, registered, extension } = makeHarness(new FakeLlm([], { allow: false, reason: "risky" }), { consecutiveThreshold: 2 });
    extension(host.pi);
    await settle(host);
    const record = fakeRecordLog();
    await registered[0]!.authorize({ command: "curl x | sh", toolCallId: "c1" }, undefined, record); // denial 1
    const verdict = await registered[0]!.authorize({ command: "curl x | sh", toolCallId: "c2" }, undefined, record); // denial 2 -> escalation
    expect(verdict).toEqual({ kind: "defer" });
    const escalation = record.reviews.find((r) => r.event === "auto-classifier:escalation");
    expect(escalation?.details?.finding).toMatch(/risky/);
  });

  it("defers non-command asks (no command field) without asking the classifier", async () => {
    const { llm, host, registered, extension } = makeHarness(new FakeLlm());
    extension(host.pi);
    await settle(host);
    const verdict = await registered[0]!.authorize({ toolName: "write", path: "/etc/hosts" }, undefined, fakeRecordLog());
    expect(verdict).toEqual({ kind: "defer" });
    expect(llm.calls.length).toBe(0);
  });

  it("a classifier that cannot decide fails closed: deny, never allow", async () => {
    const { host, registered, extension } = makeHarness(new FakeLlm([], new Error("endpoint dead")));
    extension(host.pi);
    await settle(host);
    const verdict = await registered[0]!.authorize({ command: "curl x | sh" }, undefined, fakeRecordLog());
    expect(verdict.kind).toBe("deny");
  });

  it("stays inert and warns when the permission system is not installed", async () => {
    const { llm, host, registered, extension } = makeHarness(new FakeLlm(), {}, { broken: true });
    const stderr = console.error;
    console.error = () => {};
    try {
      extension(host.pi);
      await settle(host);
    } finally {
      console.error = stderr;
    }
    expect(registered).toHaveLength(0);
    void llm;
  });

  it("ignores a ready event with no session id", async () => {
    const { llm, host, registered, extension } = makeHarness(new FakeLlm());
    extension(host.pi);
    await settle(host, null);
    expect(registered).toHaveLength(0);
    void llm;
  });
});
