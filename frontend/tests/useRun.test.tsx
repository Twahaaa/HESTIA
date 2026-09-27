import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useRun } from "../src/hooks/useRun";
import { mockApi, RUN_ID, runDetail } from "./mockApi";

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function flush(ms = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

it("polls one request at a time and stops at a terminal state", async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  let count = 0;
  const { fetchMock } = mockApi({
    [`/api/runs/${RUN_ID}`]: () => {
      count += 1;
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      inFlight -= 1;
      return {
        body:
          count < 3
            ? runDetail("running", "in_progress")
            : runDetail("completed", "report_published"),
      };
    },
  });
  const { result } = renderHook(() => useRun(RUN_ID, { intervalMs: 100 }));
  await flush();
  expect(result.current.status).toBe("polling");
  await flush(100);
  await flush(100);
  expect(result.current.status).toBe("done");
  expect(result.current.run?.state).toBe("completed");
  await flush(1000);
  expect(fetchMock).toHaveBeenCalledTimes(3);
  expect(maxInFlight).toBe(1);
});

it("reports a lost connection after bounded retries and resumes on request", async () => {
  let down = true;
  const { fetchMock } = mockApi({
    [`/api/runs/${RUN_ID}`]: () =>
      down ? "network" : { body: runDetail("failed", "cancelled") },
  });
  const { result } = renderHook(() =>
    useRun(RUN_ID, { intervalMs: 100, maxFailures: 3 }),
  );
  await flush();
  expect(result.current.status).toBe("reconnecting");
  await flush(200);
  await flush(400);
  expect(result.current.status).toBe("lost");
  expect(result.current.error).toMatch(/Lost connection/);
  const calls = fetchMock.mock.calls.length;
  await flush(5000);
  expect(fetchMock.mock.calls.length).toBe(calls);
  down = false;
  act(() => result.current.retry());
  await flush();
  expect(result.current.status).toBe("done");
  expect(result.current.run?.outcome).toBe("cancelled");
});

it("aborts the request in flight and stops scheduling on unmount", async () => {
  const { fetchMock } = mockApi({
    [`/api/runs/${RUN_ID}`]: runDetail("running", "in_progress"),
  });
  const { unmount } = renderHook(() => useRun(RUN_ID, { intervalMs: 100 }));
  await flush();
  unmount();
  const calls = fetchMock.mock.calls.length;
  await flush(2000);
  expect(fetchMock.mock.calls.length).toBe(calls);
  const signal = (fetchMock.mock.calls[0][1] as RequestInit).signal;
  expect(signal?.aborted).toBe(true);
});

it("stops after the polling limit instead of running forever", async () => {
  mockApi({ [`/api/runs/${RUN_ID}`]: runDetail("running", "in_progress") });
  const { result } = renderHook(() =>
    useRun(RUN_ID, { intervalMs: 10, maxPolls: 3 }),
  );
  await flush();
  await flush(10);
  await flush(10);
  expect(result.current.status).toBe("stopped");
});

it("stays idle without a run", () => {
  mockApi({});
  const { result } = renderHook(() => useRun(null));
  expect(result.current.status).toBe("idle");
});
