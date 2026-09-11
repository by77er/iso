import { test, expect } from "@playwright/test";
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
