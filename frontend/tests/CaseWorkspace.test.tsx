import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import {
  baseRoutes,
  CASE_ID,
  caseDetail,
  evidence,
  mockApi,
  RUN_ID,
  report,
  runDetail,
  runSummary,
  workspace,
} from "./mockApi";

beforeEach(() => {
  window.history.replaceState(null, "", `/#/cases/${CASE_ID}/runs/${RUN_ID}`);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function completedRoutes(extra: Record<string, unknown> = {}) {
  return baseRoutes({
    [`/api/cases/${CASE_ID}`]: caseDetail([
      runSummary("completed", "report_published"),
    ]),
    [`/api/runs/${RUN_ID}`]: runDetail("completed", "report_published"),
    [`/api/runs/${RUN_ID}/report`]: report,
    [`/api/runs/${RUN_ID}/evidence`]: evidence,
    ...extra,
  });
}

it("renders an insufficient-evidence report as an abstention, labelled as a fixture", async () => {
  mockApi(completedRoutes());
  render(<App />);
  expect(
    await screen.findByRole("heading", {
      name: "Insufficient evidence — the agent abstained",
    }),
  ).toBeInTheDocument();
  const reportView = screen.getByRole("article", {
    name: "Insufficient evidence — the agent abstained",
  });
  expect(within(reportView).getByText(/not a live model/)).toBeInTheDocument();
  expect(within(reportView).getByText("none")).toBeInTheDocument();
  expect(
    within(reportView).getByText(/no containment or remediation/),
  ).toBeInTheDocument();
  expect(within(reportView).getByText("demo-bastion")).toBeInTheDocument();
  expect(within(reportView).queryByText(/malicious/i)).not.toBeInTheDocument();
});

it("shows the trace with tool, request, evidence count and timing", async () => {
  mockApi(completedRoutes());
  render(<App />);
  const trace = await screen.findByRole("region", {
    name: "Investigation trace",
  });
  expect(within(trace).getByText("get_events")).toBeInTheDocument();
  expect(within(trace).getByText("Asked for: limit=10")).toBeInTheDocument();
  expect(
    within(trace).getByText("3 returned · 1 evidence reference(s)"),
  ).toBeInTheDocument();
  expect(within(trace).getByText("9 ms")).toBeInTheDocument();
  expect(within(trace).getByText("Recorded hypothesis")).toBeInTheDocument();
  expect(
    within(trace).getByText(/No private model reasoning/),
  ).toBeInTheDocument();
});

it("opens a citation in an accessible drawer with the exact source line", async () => {
  const { calls } = mockApi(completedRoutes());
  render(<App />);
  const open = await screen.findByRole("button", {
    name: "Open event ev-2222222222",
  });
  open.focus();
  fireEvent.click(open);
  const dialog = await screen.findByRole("dialog", {
    name: "Evidence ev-2222222222",
  });
  expect(
    await within(dialog).findByText(/Failed password for invalid user admin/),
  ).toBeInTheDocument();
  expect(
    within(dialog).getByText(/synthetic-demo\/auth.log:3/),
  ).toBeInTheDocument();
  expect(
    calls.some(
      (call) => call.url === `/api/runs/${RUN_ID}/evidence/ev-2222222222`,
    ),
  ).toBe(true);
  const close = within(dialog).getByRole("button", { name: "Close" });
  expect(close).toHaveFocus();
  fireEvent.keyDown(dialog, { key: "Escape" });
  await waitFor(() =>
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
  );
  expect(open).toHaveFocus();
});

it("shows an unresolvable citation as such instead of a broken link", async () => {
  mockApi(
    completedRoutes({
      [`/api/runs/${RUN_ID}/report`]: {
        ...report,
        citations_resolvable: false,
        citation_note:
          "This run's local handle map is missing, so its citations cannot be opened.",
        findings: [
          {
            ...report.findings[0],
            citations: [
              {
                handle: "ev-2222222222",
                kind: "event",
                resolvable: false,
                reason: "the local handle map for this run is missing",
              },
            ],
          },
        ],
      },
    }),
  );
  render(<App />);
  expect(
    await screen.findByText(/cannot be opened: the local handle map/),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: /Open event/ }),
  ).not.toBeInTheDocument();
});

it.each([
  [
    "cancelled",
    "cancelled",
    "cancelled by the analyst",
    "Cancelled — no report",
  ],
  [
    "failed",
    "interrupted",
    "interrupted: the workspace process stopped",
    "Interrupted — no report",
  ],
  [
    "failed",
    "grounding_failed",
    "the report failed citation validation after one repair attempt",
    "Report refused — citations failed validation",
  ],
])(
  "never presents a %s (%s) run as complete",
  async (state, outcome, reason, label) => {
    const grounding =
      outcome === "grounding_failed"
        ? {
            grounded: false,
            checked_handles: 1,
            issues: [
              {
                kind: "uncited_handle",
                detail: "no tool returned it",
                handle: "ev-ffff",
              },
            ],
            repair_attempted: true,
            note: "",
          }
        : null;
    const { calls } = mockApi(
      baseRoutes({
        [`/api/cases/${CASE_ID}`]: caseDetail([
          runSummary(state, outcome, { incomplete_reason: reason }),
        ]),
        [`/api/runs/${RUN_ID}`]: runDetail(state, outcome, {
          incomplete_reason: reason,
          grounding,
        }),
      }),
    );
    render(<App />);
    expect(
      await screen.findByRole("heading", { name: label }),
    ).toBeInTheDocument();
    expect(screen.getByText(/nothing here is a verdict/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Retry as a new fixture run" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByText(/Insufficient evidence — the agent abstained/),
    ).not.toBeInTheDocument();
    expect(calls.some((call) => call.url.endsWith("/report"))).toBe(false);
    if (grounding)
      expect(screen.getByText(/uncited handle/)).toBeInTheDocument();
  },
);

it("starts a fixture run with an idempotency key and follows it to its report", async () => {
  let runState = "running";
  const { calls } = mockApi(
    baseRoutes({
      [`/api/cases/${CASE_ID}`]: () => ({
        body: caseDetail(
          runState === "running"
            ? []
            : [runSummary("completed", "report_published")],
        ),
      }),
      [`/api/cases/${CASE_ID}/runs`]: () => ({
        status: 202,
        body: {
          created: true,
          run: runDetail("running", "in_progress", { steps: [] }),
        },
      }),
      [`/api/runs/${RUN_ID}`]: () => {
        const body =
          runState === "running"
            ? runDetail("running", "in_progress", {
                steps: [],
                report_available: false,
              })
            : runDetail("completed", "report_published");
        runState = "completed";
        return { body };
      },
      [`/api/runs/${RUN_ID}/report`]: report,
    }),
  );
  window.history.replaceState(null, "", `/#/cases/${CASE_ID}`);
  render(<App />);
  const button = await screen.findByRole("button", {
    name: "Run fixture investigation",
  });
  fireEvent.click(button);
  expect(
    await screen.findByRole(
      "heading",
      { name: "Insufficient evidence — the agent abstained" },
      {
        timeout: 4000,
      },
    ),
  ).toBeInTheDocument();
  const post = calls.find((call) => call.init?.method === "POST");
  const headers = post?.init?.headers as Record<string, string>;
  expect(headers["Idempotency-Key"]).toMatch(/^[A-Za-z0-9_-]{8,128}$/);
  expect(JSON.parse(String(post?.init?.body))).toEqual({
    mode: "fixture",
    confirm_hosted: false,
  });
  expect(window.location.hash).toBe(`#/cases/${CASE_ID}/runs/${RUN_ID}`);
});

it("explains a conflict when another investigation is active", async () => {
  mockApi(
    baseRoutes({
      [`/api/cases/${CASE_ID}`]: caseDetail(),
      [`/api/cases/${CASE_ID}/runs`]: () => ({
        status: 409,
        body: {
          detail: {
            code: "run_active",
            message: "another investigation is still active",
            run_id: "f".repeat(32),
            case_id: "case-ffffffffffffffffffff",
          },
        },
      }),
    }),
  );
  window.history.replaceState(null, "", `/#/cases/${CASE_ID}`);
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Run fixture investigation" }),
  );
  expect(
    await screen.findByText(/One case runs at a time/),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Open the active case" }),
  ).toBeInTheDocument();
});

it("asks for explicit confirmation before a hosted run", async () => {
  const { calls } = mockApi(
    baseRoutes({
      "/api/workspace": {
        ...workspace,
        provider: {
          configured: true,
          provider: "groq",
          model: "example-model",
          fixture: false,
          reason: null,
        },
      },
      [`/api/cases/${CASE_ID}`]: caseDetail(),
    }),
  );
  window.history.replaceState(null, "", `/#/cases/${CASE_ID}`);
  render(<App />);
  expect(
    await screen.findByText(
      /live workspace completion is not established by it/,
    ),
  ).toBeInTheDocument();
  fireEvent.click(
    await screen.findByRole("button", { name: "Run with Groq…" }),
  );
  expect(screen.getByText(/may incur cost/)).toBeInTheDocument();
  expect(calls.some((call) => call.init?.method === "POST")).toBe(false);
});

it("never turns a failed hosted retry into a fixture run", async () => {
  const hosted = {
    fixture: false,
    provider: "groq",
    model: "example-model",
    execution: {
      kind: "hosted",
      label: "Hosted provider run (groq / example-model)",
    },
    incomplete_reason: "rate limit allowance exhausted",
  };
  const { calls } = mockApi(
    baseRoutes({
      "/api/workspace": {
        ...workspace,
        provider: {
          configured: true,
          provider: "groq",
          model: "example-model",
          fixture: false,
          reason: null,
        },
      },
      [`/api/cases/${CASE_ID}`]: caseDetail([
        runSummary("failed", "budget_exhausted", hosted),
      ]),
      [`/api/runs/${RUN_ID}`]: runDetail("failed", "budget_exhausted", hosted),
    }),
  );
  window.history.replaceState(null, "", `/#/cases/${CASE_ID}`);
  render(<App />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry hosted run…" }),
  );
  // The confirmation sits in the investigation panel, far from the retry
  // button; it must take focus so the click visibly does something.
  const confirm = screen.getByRole("group", {
    name: /Send redacted evidence to a hosted provider/,
  });
  await waitFor(() => expect(confirm).toHaveFocus());
  expect(calls.some((call) => call.init?.method === "POST")).toBe(false);
});

it("the skip link moves focus without closing the open case", async () => {
  mockApi(completedRoutes());
  render(<App />);
  expect(
    await screen.findByRole("heading", { level: 2, name: /@/ }),
  ).toBeInTheDocument();
  const before = window.location.hash;
  fireEvent.click(
    screen.getByRole("link", { name: "Skip to the case workspace" }),
  );
  expect(window.location.hash).toBe(before);
  expect(document.getElementById("workspace")).toHaveFocus();
  expect(
    screen.getByRole("heading", { level: 2, name: /@/ }),
  ).toBeInTheDocument();
});

it("records a review disposition and shows it in the history", async () => {
  let saved = false;
  const disposition = {
    disposition_id: "d1",
    case_id: CASE_ID,
    run_id: RUN_ID,
    disposition: "inconclusive",
    note: "Needs host context.",
    actor: "local-analyst",
    recorded_at: "2026-09-25T10:05:00Z",
  };
  mockApi(
    completedRoutes({
      [`/api/cases/${CASE_ID}`]: () => ({
        body: {
          ...caseDetail([runSummary("completed", "report_published")]),
          dispositions: saved ? [disposition] : [],
        },
      }),
      [`/api/cases/${CASE_ID}/dispositions`]: (init?: RequestInit) => {
        saved = true;
        expect(JSON.parse(String(init?.body))).toMatchObject({
          disposition: "inconclusive",
          note: "Needs host context.",
          run_id: RUN_ID,
        });
        return { status: 201, body: disposition };
      },
    }),
  );
  render(<App />);
  const review = await screen.findByRole("region", { name: "Analyst review" });
  expect(within(review).getByText(/not a training label/)).toBeInTheDocument();
  fireEvent.click(within(review).getByLabelText(/Inconclusive/));
  fireEvent.change(within(review).getByLabelText("Note (optional)"), {
    target: { value: "Needs host context." },
  });
  fireEvent.click(
    within(review).getByRole("button", { name: "Save disposition" }),
  );
  expect(
    await within(review).findByText(/Saved “Inconclusive”/),
  ).toBeInTheDocument();
  expect(
    await within(review).findByText("Needs host context."),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: /contain|isolate|block|remediat/i }),
  ).not.toBeInTheDocument();
});
