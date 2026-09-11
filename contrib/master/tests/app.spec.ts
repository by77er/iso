import { test, expect } from "@playwright/test";
test.use({ colorScheme: "dark" });

test("tool calls share an aligned compact group", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.route("**/api/sessions/*/events?*", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    const after = Number(
      new URL(route.request().url()).searchParams.get("after"),
    );
    await route.fulfill({
      json: {
        ...body,
        events: after
          ? []
          : [
              { seq: 1, type: "assistant_start" },
              {
                seq: 2,
                type: "tool_start",
                id: "a",
                name: "read",
                args: { path: "README.md" },
              },
              { seq: 3, type: "tool_end", id: "a", result: "File contents" },
              { seq: 4, type: "message", role: "assistant", text: "" },
              {
                seq: 5,
                type: "tool_start",
                id: "b",
                name: "bash",
                args: { command: "pwd" },
              },
              { seq: 6, type: "tool_end", id: "b", result: "/home/coder" },
              {
                seq: 7,
                type: "message",
                role: "assistant",
                text: "Workspace inspected.",
              },
            ],
      },
    });
  });
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("browser-test-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("button", { name: "New agent", exact: true }).click();
  await page.getByLabel("Agent name").fill("Tool layout");
  await page.getByRole("button", { name: "Create agent", exact: true }).click();
  await expect(page.locator(".tool-group")).toHaveCount(1);
  await expect(page.locator(".tool-group .tool-card")).toHaveCount(2);
  await expect(page.locator(".message.assistant")).toHaveCount(1);
  const icon = await page.locator(".tool-group-icon").boundingBox();
  const pill = await page.locator(".tool-card summary").first().boundingBox();
  expect(
    Math.abs(icon!.y + icon!.height / 2 - pill!.y - pill!.height / 2),
  ).toBeLessThan(2);
  await page.screenshot({ path: "test-results/tools.png", fullPage: true });
  await page.locator(".tool-card summary").first().click();
  await expect(page.locator(".tool-card[open]")).toContainText("File contents");
});

test("theme follows the system and remembers an explicit choice", async ({
  page,
}) => {
  await page.goto("/");
  const root = page.locator("html");
  await expect(root).toHaveAttribute("data-theme", "dark");
  await expect(page.locator("body")).toHaveCSS(
    "background-color",
    "rgb(13, 13, 16)",
  );
  await page.getByLabel("Color theme").selectOption("light");
  await expect(root).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(page.getByLabel("Color theme")).toHaveValue("light");
  await expect(root).toHaveAttribute("data-theme", "light");
  await page.getByLabel("Color theme").selectOption("system");
  await expect(root).toHaveAttribute("data-theme", "dark");
  await page.emulateMedia({ colorScheme: "light" });
  await expect(root).toHaveAttribute("data-theme", "light");
});

test("agent-first flow, stream, sleep, wake, fleet, and close", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("browser-test-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "A workspace for every idea." }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Create your first agent" }).click();
  await page.getByLabel("Agent name").fill("Build a dashboard");
  await page.getByRole("button", { name: "Create agent", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Build a dashboard" }),
  ).toBeVisible();
  await expect(page.locator(".header-actions .badge")).toHaveText("Ready");
  await page.getByLabel("Model", { exact: true }).selectOption("demo/worker");
  await expect(page.getByLabel("Model", { exact: true })).toHaveValue(
    "demo/worker",
  );
  await page
    .getByLabel("Message your agent")
    .fill("Help me build a dashboard.");
  await page.getByRole("button", { name: "Send message" }).click();
  await expect(page.locator(".message.assistant")).toContainText(
    "This is a demo agent.",
  );
  await expect(page.locator(".header-actions .badge")).toHaveText("Ready");
  await page.getByRole("button", { name: "Workspace details" }).click();
  const vmBefore = await page.locator(".workspace-details").textContent();
  await page.getByRole("button", { name: "Sleep now" }).click();
  await expect(page.locator(".header-actions .badge")).toHaveText("Asleep");
  await page
    .getByLabel("Message your agent")
    .fill("Continue where we left off.");
  await page.getByRole("button", { name: "Send message" }).click();
  await expect(page.locator(".message.assistant")).toHaveCount(2);
  await expect(page.locator(".header-actions .badge")).toHaveText("Ready");
  expect(await page.locator(".workspace-details").textContent()).toBe(vmBefore);
  await expect(page.getByText("Private microVM", { exact: true })).toHaveCount(
    0,
  );
  await expect(page.getByRole("button", { name: "Show closed" })).toBeVisible();
  const userBubble = await page
    .locator(".message.user .message-body")
    .first()
    .boundingBox();
  const agentResponse = await page
    .locator(".message.assistant .message-body")
    .first()
    .boundingBox();
  expect(userBubble!.x).toBeGreaterThan(agentResponse!.x);
  await expect(
    page.locator(".message.assistant .message-label").first(),
  ).toHaveText("");
  await page.screenshot({ path: "test-results/workspace.png", fullPage: true });
  await page.getByRole("button", { name: "Control planes" }).click();
  await expect(
    page.getByRole("heading", { name: "east", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "west", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: /Build a dashboard/ }).click();
  await expect(page.locator(".message.assistant")).toHaveCount(2); // durable cursor replay after remount
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Close agent", exact: true }).click();
  await expect(page.locator(".header-actions .badge")).toHaveText("Closed");
  await expect(page.getByLabel("Message your agent")).toBeDisabled();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(
    page.getByRole("button", { name: "Sign in", exact: true }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});

test("swarm has separate models and a navigable planner-worker tree", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("browser-test-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("button", { name: "New agent", exact: true }).click();
  await page.getByLabel("Agent name").fill("Planner root");
  await page.getByLabel("Swarm mode").check();
  await page.getByLabel("Planner model").selectOption("demo/planner");
  await page.getByLabel("Worker model").selectOption("demo/worker");
  await page.getByRole("button", { name: "Create swarm", exact: true }).click();
  await page.locator(".swarm-panel > summary").click();
  await expect(page.locator(".conversation-options")).toContainText(
    "Read-only planner · demo/planner",
  );
  await page
    .getByRole("button", { name: "Schedule child", exact: true })
    .click();
  await page.getByLabel("Child name").fill("Subplanner");
  await page.getByLabel("Role", { exact: true }).selectOption("planner");
  await page
    .getByLabel("Task", { exact: true })
    .fill("Plan the implementation and report to your parent.");
  await page.getByRole("button", { name: "Schedule", exact: true }).click();
  await page
    .locator(".sidebar-tree")
    .getByRole("button", { name: /Subplanner/ })
    .click();
  await expect(
    page.getByRole("heading", { name: "Subplanner", exact: true }),
  ).toBeVisible();
  await page.locator(".swarm-panel > summary").click();
  await expect(page.locator(".conversation-options")).toContainText(
    "Read-only planner · demo/planner",
  );
  await page
    .getByRole("button", { name: "Schedule child", exact: true })
    .click();
  await page.getByLabel("Child name").fill("Implementation worker");
  await page
    .getByLabel("Task", { exact: true })
    .fill("Implement the plan and report results.");
  await page.getByRole("button", { name: "Schedule", exact: true }).click();
  await page
    .locator(".sidebar-tree")
    .getByRole("button", { name: /Implementation worker/ })
    .click();
  await expect(page.locator(".conversation-options")).toContainText(
    "Worker · demo/worker",
  );
  await expect(
    page.getByRole("button", { name: "Schedule child", exact: true }),
  ).toHaveCount(0);
  await expect(page.locator(".sidebar-tree ul ul .session-link")).toHaveCount(
    1,
  );
  await page
    .getByRole("button", { name: "Collapse Planner root", exact: true })
    .click();
  await expect(page.locator(".sidebar-tree ul")).toHaveCount(0);
  await page
    .getByRole("button", { name: "Expand Planner root", exact: true })
    .click();
  await expect(page.locator(".sidebar-tree ul ul .session-link")).toHaveCount(
    1,
  );
  await expect(page.locator(".swarm-panel")).not.toHaveAttribute("open", "");
  await expect(page.locator(".swarm-mail")).toContainText("Implement the plan");
  await expect(
    page.getByRole("article", { name: "Message from parent" }),
  ).toContainText("Subplanner");
  await expect(page.locator(".swarm-message")).toContainText(
    "Implement the plan and report results.",
  );
  await expect(page.locator(".message.user")).toHaveCount(0);
  await page.route("**/api/sessions/*/events?*", async (route) => {
    const response = await route.fetch();
    const body = await response.json();
    if (
      body.session.swarm?.role === "worker" &&
      new URL(route.request().url()).searchParams.get("after") === "0"
    ) {
      body.events.push(
        {
          seq: 100000,
          type: "tool_start",
          id: "report",
          name: "swarm_send",
          args: {
            recipient: body.session.swarm.parent,
            message:
              "Implementation verified.\nAll checks passed.\nChanged the game engine.\nNo outstanding blockers.\nReady for integration.",
          },
        },
        {
          seq: 100001,
          type: "tool_end",
          id: "report",
          result: { queued: true },
        },
      );
    }
    await route.fulfill({ json: body });
  });
  await page
    .getByRole("button", { name: "Control planes", exact: true })
    .click();
  await page
    .locator(".sidebar-tree .session-link")
    .filter({ hasText: "Implementation worker" })
    .click();
  const outgoing = page.getByRole("article", { name: "Message to parent" });
  await expect(outgoing).toContainText("Subplanner");
  await expect(outgoing).toContainText("Implementation verified.");
  await expect(outgoing).toContainText("Queued");
  await expect(
    page
      .getByRole("article", { name: "Message from parent" })
      .getByRole("button", { name: "Expand message" }),
  ).toHaveCount(0);
  const expand = outgoing.getByRole("button", { name: "Expand message" });
  await expect(expand).toHaveAttribute("aria-expanded", "false");
  const preview = outgoing.locator(".swarm-message-body p");
  const collapsedHeight = (await preview.boundingBox())!.height;
  expect(collapsedHeight).toBeLessThanOrEqual(43);
  await expand.click();
  await expect(
    outgoing.getByRole("button", { name: "Show less" }),
  ).toHaveAttribute("aria-expanded", "true");
  expect((await preview.boundingBox())!.height).toBeGreaterThan(
    collapsedHeight * 2,
  );
  await outgoing.getByRole("button", { name: "Show less" }).click();
  await expect(expand).toBeVisible();
  await expect(page.locator(".tool-card")).toHaveCount(0);
  await page.screenshot({ path: "test-results/swarm.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
});
