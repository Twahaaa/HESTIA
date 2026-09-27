import { type ConsoleMessage, expect, type Page, test } from "@playwright/test";

// Every test starts from an empty demo workspace, through the real reset endpoint.
test.beforeEach(async ({ request }) => {
  const response = await request.post("/api/workspace/reset", {
    data: { confirm: "reset demo workspace" },
  });
  expect(response.ok()).toBeTruthy();
});

function watchConsole(page: Page): string[] {
  const problems: string[] = [];
  page.on("console", (message: ConsoleMessage) => {
    if (message.type() === "error") problems.push(message.text());
  });
  page.on("pageerror", (error) => problems.push(error.message));
  return problems;
}

async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(
    () =>
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
}

async function shot(
  page: Page,
  name: string,
  projectName: string,
  fullPage = true,
) {
  await page.screenshot({
    path: `test-results/screenshots/${projectName}-${name}.png`,
    fullPage,
  });
}

async function openCase(page: Page, who: RegExp) {
  const queue = page.getByRole("region", { name: "Cases" });
  await queue.getByRole("button", { name: who }).click();
  await expect(
    page.getByRole("heading", { level: 2, name: /@demo-/ }),
  ).toBeVisible();
}

test("synthetic case: investigate, open citations, record a review", async ({
  page,
}, testInfo) => {
  const problems = watchConsole(page);
  await page.goto("/");
  const queue = page.getByRole("region", { name: "Cases" });
  await expect(
    queue.getByText(/A missing score is not evidence of normal behaviour/),
  ).toBeVisible();
  await expect(
    queue.getByRole("button", { name: /admin@demo-bastion/ }),
  ).toContainText("Unscored");
  await expect(
    page.getByText("Unavailable — cases are unscored"),
  ).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await shot(page, "queue", testInfo.project.name);

  await openCase(page, /admin@demo-bastion/);
  await expect(
    page.getByText(/Failed password for invalid user admin/).first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "Run fixture investigation" }).click();

  // The first poll is immediate and the run is paced, so the in-progress state
  // is asserted before any tool step: waiting for a step first would race the
  // one-second poll against the end of the run.
  await expect(
    page.getByText(/There is no report until the run completes/),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Cancel run" })).toBeVisible();
  const trace = page.getByRole("region", { name: "Investigation trace" });
  await expect(trace.getByText("get_session", { exact: true })).toBeVisible();

  const reportHeading = page.getByRole("heading", {
    name: "Insufficient evidence — the agent abstained",
  });
  await expect(reportHeading).toBeVisible({ timeout: 15_000 });
  const report = page.getByRole("article", {
    name: "Insufficient evidence — the agent abstained",
  });
  await expect(report.getByText(/not a live model/)).toBeVisible();
  await expect(report.getByText(/no containment or remediation/)).toBeVisible();
  await expect(
    trace.getByText("get_normality_context", { exact: true }),
  ).toBeVisible();
  await expect(
    trace.getByText("search_attack_patterns", { exact: true }),
  ).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await shot(page, "report", testInfo.project.name);

  await report.getByRole("button", { name: /^Open event ev-/ }).click();
  const drawer = page.getByRole("dialog");
  await expect(
    drawer.getByText(/Failed password for invalid user admin/),
  ).toBeVisible();
  await expect(drawer.getByText(/synthetic-demo\/auth\.log:\d+/)).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await shot(page, "citation", testInfo.project.name, false);
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();

  await report.getByRole("button", { name: /^Open session se-/ }).click();
  await expect(
    page.getByRole("dialog").getByText(/Session in synthetic-demo/),
  ).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Close" }).click();

  const review = page.getByRole("region", { name: "Analyst review" });
  await review.getByLabel(/Inconclusive/).check();
  await review.getByLabel("Note (optional)").fill("Needs host owner context.");
  await review.getByLabel(/Your name/).fill("Demo Reviewer");
  await review.getByRole("button", { name: "Save disposition" }).click();
  await expect(
    review.getByText(/Saved “Inconclusive” by Demo Reviewer/),
  ).toBeVisible();

  // Persisted server-side: a fresh page load shows the same history and queue state.
  await page.reload();
  const reloaded = page.getByRole("region", { name: "Analyst review" });
  await expect(reloaded.getByText("Needs host owner context.")).toBeVisible();
  await expect(
    page
      .getByRole("region", { name: "Cases" })
      .getByText("Reviewed: Inconclusive"),
  ).toHaveCount(testInfo.project.name === "desktop" ? 1 : 0);
  expect(problems).toEqual([]);
});

test("a cancelled run ends without a report and can be retried", async ({
  page,
}) => {
  const problems = watchConsole(page);
  await page.goto("/");
  await openCase(page, /leo@demo-bastion/);
  await page.getByRole("button", { name: "Run fixture investigation" }).click();
  // Cancel as soon as the running state is shown, well before the paced run ends.
  await page.getByRole("button", { name: "Cancel run" }).click();
  await expect(
    page.getByRole("heading", { name: "Cancelled — no report" }),
  ).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText(/nothing here is a verdict/)).toBeVisible();
  await expect(
    page.getByRole("heading", { name: /Insufficient evidence/ }),
  ).toHaveCount(0);
  await page
    .getByRole("button", { name: "Retry as a new fixture run" })
    .click();
  await expect(
    page.getByRole("heading", {
      name: "Insufficient evidence — the agent abstained",
    }),
  ).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText("Cancelled — no report")).toBeVisible();
  expect(problems).toEqual([]);
});

test("keyboard only: select, investigate, open and close a citation", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("region", { name: "Cases" }).getByRole("button").first(),
  ).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to the case workspace" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");

  const firstCase = page
    .getByRole("region", { name: "Cases" })
    .getByRole("button")
    .first();
  for (
    let i = 0;
    i < 10 &&
    !(await firstCase.evaluate((el) => el === document.activeElement));
    i++
  ) {
    await page.keyboard.press("Tab");
  }
  await expect(firstCase).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("heading", { level: 2, name: /@demo-/ }),
  ).toBeFocused();

  const run = page.getByRole("button", { name: "Run fixture investigation" });
  for (
    let i = 0;
    i < 30 && !(await run.evaluate((el) => el === document.activeElement));
    i++
  ) {
    await page.keyboard.press("Tab");
  }
  await expect(run).toBeFocused();
  await page.keyboard.press("Enter");
  const report = page.getByRole("article", { name: /Insufficient evidence/ });
  await expect(report).toBeVisible({ timeout: 15_000 });

  const citation = report.getByRole("button", { name: /^Open event ev-/ });
  await citation.focus();
  await page.keyboard.press("Enter");
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("button", { name: "Close" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(dialog.getByRole("button", { name: "Close" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(citation).toBeFocused();
});

test("narrow and wide layouts keep every view inside the viewport", async ({
  page,
}, testInfo) => {
  await page.goto("/");
  const queue = page.getByRole("region", { name: "Cases" });
  await expect(queue).toBeVisible();
  await expectNoHorizontalOverflow(page);
  await openCase(page, /maya@demo-app/);
  await expectNoHorizontalOverflow(page);
  const back = page.getByRole("button", { name: "Back to cases" });
  if (testInfo.project.name === "mobile-390") {
    await expect(queue).toBeHidden();
    await expect(back).toBeVisible();
    await shot(page, "case-detail", testInfo.project.name);
    await back.click();
    await expect(queue).toBeVisible();
    await expect(page.getByText("No case selected")).toBeHidden();
  } else {
    await expect(queue).toBeVisible();
    await expect(back).toBeHidden();
  }
  await expectNoHorizontalOverflow(page);
});

test("API outage is shown as an outage and recovers", async ({
  page,
}, testInfo) => {
  await page.goto("/");
  await expect(
    page.getByRole("region", { name: "Cases" }).getByRole("button").first(),
  ).toBeVisible();

  await page.route("**/api/**", (route) => route.abort("connectionrefused"));
  await page.reload();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "The workspace API could not be reached." })
      .first(),
  ).toBeVisible();
  await expect(page.getByText(/No prepared cases/)).toHaveCount(0);
  await shot(page, "outage", testInfo.project.name);

  await page.unroute("**/api/**");
  await page.getByRole("button", { name: "Try again" }).first().click();
  await expect(page.getByText(/Service online/)).toBeVisible();
});

test("a lost connection mid-run is reported and polling resumes", async ({
  page,
}) => {
  await page.goto("/");
  await openCase(page, /deploy@demo-app/);
  await page.getByRole("button", { name: "Run fixture investigation" }).click();
  await expect(
    page
      .getByRole("region", { name: "Investigation trace" })
      .getByText("get_session", { exact: true }),
  ).toBeVisible();

  await page.route("**/api/runs/**", (route) =>
    route.abort("connectionrefused"),
  );
  await expect(
    page.getByText(/Lost connection to the workspace API/),
  ).toBeVisible({
    timeout: 15_000,
  });
  await page.unroute("**/api/runs/**");
  await page.getByRole("button", { name: "Resume" }).click();
  await expect(
    page.getByRole("heading", {
      name: "Insufficient evidence — the agent abstained",
    }),
  ).toBeVisible({ timeout: 15_000 });
});
