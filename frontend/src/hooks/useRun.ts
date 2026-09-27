import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, describeError, isTransient } from "../api/client";
import type { RunDetail } from "../api/contracts";

export type RunPollStatus =
  | "idle"
  | "loading"
  | "polling"
  | "done"
  | "reconnecting"
  | "lost"
  | "stopped"
  | "error";

export type RunPoll = {
  run: RunDetail | null;
  status: RunPollStatus;
  error: string | null;
  /** Resume after a lost connection or a stopped poll. */
  retry: () => void;
};

export type PollOptions = {
  intervalMs?: number;
  /** Consecutive transient failures tolerated before reporting a lost connection. */
  maxFailures?: number;
  /** Upper bound on requests for one run, so a stuck run cannot poll forever. */
  maxPolls?: number;
};

const TERMINAL = new Set(["completed", "failed", "cancelled"]);

/**
 * Follow one run until it ends.
 *
 * One request at a time: the next poll is scheduled only after the previous one
 * settles, and unmounting or switching runs aborts the request in flight. After
 * `maxFailures` transient failures in a row the hook stops and reports `lost`
 * instead of retrying indefinitely; `retry()` resumes.
 */
export function useRun(
  runId: string | null,
  options: PollOptions = {},
): RunPoll {
  const { intervalMs = 1000, maxFailures = 3, maxPolls = 900 } = options;
  const [run, setRun] = useState<RunDetail | null>(null);
  const [status, setStatus] = useState<RunPollStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const lastRunId = useRef<string | null>(null);

  const retry = useCallback(() => setAttempt((value) => value + 1), []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: attempt restarts polling on request.
  useEffect(() => {
    if (!runId) {
      setRun(null);
      setStatus("idle");
      setError(null);
      return;
    }
    if (lastRunId.current !== runId) {
      lastRunId.current = runId;
      setRun(null);
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let failures = 0;
    let polls = 0;
    let stopped = false;
    setStatus("loading");
    setError(null);

    const schedule = (delay: number) => {
      if (!stopped) timer = setTimeout(poll, delay);
    };

    async function poll() {
      if (stopped || !runId) return;
      polls += 1;
      try {
        const next = await api.run(runId, controller.signal);
        if (stopped) return;
        failures = 0;
        setRun(next);
        setError(null);
        if (TERMINAL.has(next.state)) {
          setStatus("done");
          return;
        }
        if (polls >= maxPolls) {
          setStatus("stopped");
          setError(
            "Stopped following this run after the polling limit. Resume to check again.",
          );
          return;
        }
        setStatus("polling");
        schedule(intervalMs);
      } catch (caught) {
        if (stopped || controller.signal.aborted) return;
        if (isTransient(caught)) {
          failures += 1;
          if (failures >= maxFailures) {
            setStatus("lost");
            setError(
              "Lost connection to the workspace API. The run's state is unknown.",
            );
            return;
          }
          setStatus("reconnecting");
          schedule(intervalMs * 2 ** failures);
          return;
        }
        setStatus("error");
        setError(
          caught instanceof ApiError ? caught.message : describeError(caught),
        );
      }
    }

    poll();
    return () => {
      stopped = true;
      controller.abort();
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [runId, attempt, intervalMs, maxFailures, maxPolls]);

  return { run, status, error, retry };
}
