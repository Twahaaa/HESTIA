import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import {
  baseRoutes,
  CASE_ID,
  caseDetail,
  mockApi,
  preparation,
  scoring,
} from "./mockApi";

beforeEach(() => {
  window.history.replaceState(null, "", "/");
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("shows real availability without inventing ready models", async () => {
  mockApi(baseRoutes());
  render(<App />);
  expect(await screen.findByText("Untrained")).toBeInTheDocument();
  expect(screen.getByText("not imported")).toBeInTheDocument();
  expect(screen.getByText("1,200")).toBeInTheDocument();
  expect(screen.getByText("83")).toBeInTheDocument();
  expect(
    screen.getByText(/retained outside complete sessions/),
  ).toBeInTheDocument();
  expect(
    screen.getByText("insufficient training observations"),
  ).toBeInTheDocument();
  expect(
    screen.getByText("Unavailable — cases are unscored"),
  ).toBeInTheDocument();
  expect(screen.queryByText("Ready")).not.toBeInTheDocument();
});

it("says the provider is unconfigured and fixtures are labelled", async () => {
  mockApi(baseRoutes());
  render(<App />);
  expect(
    await screen.findByText(/No hosted provider configured/),
  ).toBeInTheDocument();
  expect(
    screen.getByText(/never presented as a live model/),
  ).toBeInTheDocument();
});

it("shows an honest preparation zero state", async () => {
  mockApi(
    baseRoutes({
      "/api/datasets": { datasets: [] },
      "/api/normality/models": { models: [] },
      "/api/preparation": {
        ...preparation,
        status: "not_created",
        counts: {
          sources: 0,
          events: 0,
          parse_failures: 0,
          sessions: 0,
          unmatched_events: 0,
        },
        unmatched: { count: 0, matched_count: 0, percent_of_events: null },
        readiness: {
          ready: false,
          ready_models: 0,
          total_models: 0,
          reasons: ["evidence preparation has not been run"],
        },
      },
      "/api/cases": () => ({
        status: 503,
        body: {
          detail: {
            code: "store_unavailable",
            message: "evidence preparation has not been run",
          },
        },
      }),
    }),
  );
  render(<App />);
  expect(
    await screen.findByText(/preparation not created/),
  ).toBeInTheDocument();
  expect(
    await screen.findByText(
      "Cases could not be loaded: evidence preparation has not been run",
    ),
  ).toBeInTheDocument();
  expect(screen.queryByText("Ready")).not.toBeInTheDocument();
});

it("shows a recoverable service error", async () => {
  mockApi({
    "/api": () => ({ status: 503, body: null }),
  });
  render(<App />);
  const alerts = await screen.findAllByRole("alert");
  expect(alerts[0]).toHaveTextContent("503");
  expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
});

it("reports an unreachable API as such rather than as empty data", async () => {
  mockApi({ "/api": () => "network" });
  render(<App />);
  const alerts = await screen.findAllByRole("alert");
  expect(alerts[0]).toHaveTextContent(
    "The workspace API could not be reached.",
  );
  expect(screen.queryByText("No prepared cases.")).not.toBeInTheDocument();
});

it("lists cases as unscored with no threat label and opens one", async () => {
  mockApi(baseRoutes({ [`/api/cases/${CASE_ID}`]: caseDetail() }));
  render(<App />);
  const queue = await screen.findByRole("region", { name: "Cases" });
  expect(
    await within(queue).findByText(/A missing score is not evidence/),
  ).toBeInTheDocument();
  const item = await within(queue).findByRole("button", {
    name: /admin@demo-bastion/,
  });
  expect(item).toHaveTextContent("Unscored");
  expect(item).toHaveTextContent("Not investigated");
  expect(item).not.toHaveTextContent(/malicious|threat|attack/i);
  item.click();
  expect(
    await screen.findByRole("heading", { name: "admin@demo-bastion" }),
  ).toBeInTheDocument();
  expect(window.location.hash).toBe(`#/cases/${CASE_ID}`);
  expect(
    screen.getByText(/Failed password for invalid user admin/),
  ).toBeInTheDocument();
  expect(screen.getByText(/not a threat assessment/)).toBeInTheDocument();
});

it("shows an empty queue plainly", async () => {
  mockApi(
    baseRoutes({
      "/api/cases": {
        items: [],
        total: 0,
        limit: 20,
        offset: 0,
        dataset_id: null,
        datasets: [],
        scoring,
      },
    }),
  );
  render(<App />);
  expect(await screen.findByText(/No prepared cases/)).toBeInTheDocument();
});
