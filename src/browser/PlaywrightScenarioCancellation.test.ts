import type { BrowserContext, Page } from "playwright-core";
import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ openBrowser: vi.fn() }));
vi.mock("./PlaywrightScenarioBrowser.js", async (original) => ({
  ...(await original<typeof import("./PlaywrightScenarioBrowser.js")>()),
  openPlaywrightScenarioBrowser: mocks.openBrowser,
}));

import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { browserScenarioSchema } from "../domain/browserScenario.js";
import { PlaywrightBrowserScenarioProvider } from "./PlaywrightBrowserScenarioProvider.js";
import {
  type OpenedScenarioBrowser,
  PlaywrightScenarioBrowserCleanupOwner,
} from "./PlaywrightScenarioBrowser.js";
import { PlaywrightScenarioSession } from "./PlaywrightScenarioSession.js";

const scenario = browserScenarioSchema.parse({
  browser: { mode: "launch", executable_path: process.execPath },
  start_url: { url: "https://example.test/" },
  actions: [{ step_id: "wait", action: "wait_for_timeout", duration_ms: 1 }],
  capture: { after_each_step: ["url"] },
});

const openedBrowser = (
  cleanup: PlaywrightScenarioBrowserCleanupOwner,
): OpenedScenarioBrowser => ({
  cleanup,
  profilePath: undefined,
  context: {
    setDefaultTimeout: vi.fn(),
    setDefaultNavigationTimeout: vi.fn(),
    addCookies: vi.fn(async () => undefined),
  } as unknown as BrowserContext,
  page: {
    goto: vi.fn(async () => undefined),
    waitForTimeout: vi.fn(async () => undefined),
    url: () => "https://example.test/",
  } as unknown as Page,
  browser: {
    version: () => "test-browser",
    contexts: () => [],
    close: async () => undefined,
  },
});

const deferred = <Value>() => {
  let resolve: (value: Value | PromiseLike<Value>) => void = () => undefined;
  const promise = new Promise<Value>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
};

const cancelOpening = async () => {
  const started = deferred<void>();
  const opening = deferred<OpenedScenarioBrowser>();
  mocks.openBrowser.mockImplementationOnce(() => {
    started.resolve(undefined);
    return opening.promise;
  });
  const provider = new PlaywrightBrowserScenarioProvider((input, options) =>
    PlaywrightScenarioSession.open(input, {}, options),
  );
  const controller = new AbortController();
  const capture = provider.captureScenario(scenario, {
    signal: controller.signal,
  });
  await started.promise;
  controller.abort();
  expect(await capture).toMatchObject({
    ok: false,
    error: expect.any(AnalysisCancelledError),
  });
  return { provider, opening };
};

beforeEach(() => mocks.openBrowser.mockReset());

it.each(["none", "browser", "profile"] as const)(
  "recovers after a cancelled opening with %s release failure",
  async (failure) => {
    let releaseFails = failure !== "none";
    const settled = deferred<void>();
    const closeBrowser = vi.fn(async () => {
      if (releaseFails && failure === "browser")
        throw new Error("browser close failed");
    });
    const removeProfile = vi.fn(async () => {
      if (releaseFails && failure === "profile")
        throw new Error("profile removal failed");
    });
    const cleanup = new PlaywrightScenarioBrowserCleanupOwner({
      closeBrowser,
      removeProfile,
      onSettled: () => settled.resolve(undefined),
    });
    const nextClose = vi.fn(async () => undefined);
    const nextCleanup = new PlaywrightScenarioBrowserCleanupOwner({
      closeBrowser: nextClose,
      removeProfile: undefined,
    });
    const { provider, opening } = await cancelOpening();
    mocks.openBrowser.mockResolvedValue(openedBrowser(nextCleanup));
    opening.resolve(openedBrowser(cleanup));
    try {
      await settled.promise;
      expect(closeBrowser).toHaveBeenCalledOnce();
      expect(removeProfile).toHaveBeenCalledTimes(
        failure === "browser" ? 0 : 1,
      );
      expect(cleanup.browserClosed).toBe(failure !== "browser");
      if (releaseFails) {
        for (let attempt = 0; attempt < 2; attempt += 1) {
          expect(await provider.captureScenario(scenario)).toMatchObject({
            ok: false,
            error: { reason: "cleanup_failed" },
          });
          expect(mocks.openBrowser).toHaveBeenCalledOnce();
        }
      }
      releaseFails = false;
      const result = await provider.captureScenario(scenario);
      if (!result.ok) throw result.error;
      expect(result.value.steps.map((step) => step.status)).toEqual([
        "completed",
        "completed",
      ]);
      expect(result.value.browser.cleanup).toBe("terminated-owned-process");
      expect(mocks.openBrowser).toHaveBeenCalledTimes(2);
      await expect(provider.close()).resolves.toBeUndefined();
      expect(closeBrowser).toHaveBeenCalledTimes(failure === "browser" ? 4 : 1);
      expect(removeProfile).toHaveBeenCalledTimes(
        failure === "profile" ? 4 : 1,
      );
      expect(nextClose).toHaveBeenCalledOnce();
    } finally {
      releaseFails = false;
      await cleanup.close();
      await nextCleanup.close();
      await provider.close().catch(() => undefined);
    }
  },
);

it("settles provider shutdown after the cancelled opening arrives late", async () => {
  const closeBrowser = vi.fn(async () => undefined);
  const removeProfile = vi.fn(async () => undefined);
  const cleanup = new PlaywrightScenarioBrowserCleanupOwner({
    closeBrowser,
    removeProfile,
  });
  const { provider, opening } = await cancelOpening();
  const closed = provider.close();
  opening.resolve(openedBrowser(cleanup));
  try {
    await expect(closed).resolves.toBeUndefined();
    expect(closeBrowser).toHaveBeenCalledOnce();
    expect(removeProfile).toHaveBeenCalledOnce();
    expect(mocks.openBrowser).toHaveBeenCalledOnce();
  } finally {
    await cleanup.close();
  }
});

it("retains pending opening and release work across cleanup retry deadlines", async () => {
  vi.useFakeTimers();
  const release = deferred<void>();
  const closeStarted = deferred<void>();
  const settled = vi.fn();
  const closeBrowser = vi.fn(() => {
    closeStarted.resolve(undefined);
    return release.promise;
  });
  const removeProfile = vi.fn(async () => undefined);
  const cleanup = new PlaywrightScenarioBrowserCleanupOwner({
    closeBrowser,
    removeProfile,
    onSettled: settled,
  });
  const { provider, opening } = await cancelOpening();
  try {
    const retry = provider.captureScenario(scenario);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await retry).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisTimeoutError" },
    });
    expect(mocks.openBrowser).toHaveBeenCalledOnce();
    expect(closeBrowser).not.toHaveBeenCalled();

    opening.resolve(openedBrowser(cleanup));
    await closeStarted.promise;
    const close = expect(provider.close()).rejects.toMatchObject({
      _tag: "AnalysisTimeoutError",
    });
    await vi.advanceTimersByTimeAsync(1_000);
    await close;
    expect(cleanup.browserClosed).toBe(false);
    expect(settled).not.toHaveBeenCalled();
    expect(removeProfile).not.toHaveBeenCalled();

    release.resolve(undefined);
    await expect(provider.close()).resolves.toBeUndefined();
    expect(settled).toHaveBeenCalledExactlyOnceWith(true);
    expect(closeBrowser).toHaveBeenCalledOnce();
    expect(removeProfile).toHaveBeenCalledOnce();
  } finally {
    opening.resolve(openedBrowser(cleanup));
    release.resolve(undefined);
    await cleanup.close();
    await provider.close().catch(() => undefined);
    vi.useRealTimers();
  }
});
