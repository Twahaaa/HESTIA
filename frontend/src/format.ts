import type {
  DispositionValue,
  Outcome,
  RunState,
  Verdict,
} from "./api/contracts";

export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function formatWindow(start: string, end: string): string {
  const from = formatTime(start);
  const to = formatTime(end);
  if (from.slice(0, 10) === to.slice(0, 10))
    return `${from.slice(0, 19)}–${to.slice(11)}`;
  return `${from} – ${to}`;
}

export const OUTCOME_LABELS: Record<Outcome, string> = {
  in_progress: "In progress",
  report_published: "Report published",
  cancelled: "Cancelled — no report",
  interrupted: "Interrupted — no report",
  grounding_failed: "Report refused — citations failed validation",
  budget_exhausted: "Stopped — budget exhausted, no report",
  provider_unavailable: "Failed — provider unavailable, no report",
  failed: "Failed — no report",
};

export const STATE_LABELS: Record<RunState, string> = {
  pending: "Pending",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

export const VERDICT_LABELS: Record<Verdict, string> = {
  insufficient_evidence: "Insufficient evidence — the agent abstained",
  benign: "Agent conclusion: benign",
  suspicious: "Agent conclusion: suspicious",
  malicious: "Agent conclusion: malicious",
};

export const DISPOSITIONS: {
  value: DispositionValue;
  label: string;
  help: string;
}[] = [
  {
    value: "inconclusive",
    label: "Inconclusive",
    help: "The evidence does not settle it.",
  },
  {
    value: "benign",
    label: "Benign after review",
    help: "Your review found an ordinary explanation.",
  },
  {
    value: "suspicious",
    label: "Suspicious after review",
    help: "Your review found activity that needs follow-up outside Hestia.",
  },
  {
    value: "report_disputed",
    label: "Report disputed",
    help: "The agent's published report is wrong or unsupported.",
  },
];

export const DISPOSITION_LABELS: Record<DispositionValue, string> =
  Object.fromEntries(
    DISPOSITIONS.map((item) => [item.value, item.label]),
  ) as Record<DispositionValue, string>;

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}
