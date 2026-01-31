// @ts-check
const { test, expect, chromium } = require('@playwright/test');

const BASE_URL = 'http://localhost:3000';

test.describe('Theme Mode Toggle', () => {
  /** @type {import('@playwright/test').Browser} */
  let browser;
  /** @type {import('@playwright/test').Page} */
  let page;

  test.beforeAll(async () => {
    browser = await chromium.launch({ headless: true });
  });

  test.afterAll(async () => {
    await browser.close();
  });

  test.beforeEach(async () => {
    const context = await browser.newContext();
    page = await context.newPage();
    // Clear localStorage so each test starts fresh
    await page.goto(BASE_URL);
    await page.evaluate(() => localStorage.clear());
    await page.reload();
    await page.waitForSelector('[data-testid="theme-toggle"]');
  });

  test.afterEach(async () => {
    await page.context().close();
  });

  test('defaults to Auto mode with no localStorage set', async () => {
    const toggle = page.locator('[data-testid="theme-toggle"]');
    await expect(toggle).toHaveAttribute('data-theme-mode', 'auto');
    await expect(toggle).toContainText('Auto');
  });

  test('cycles through Auto -> Light -> Dark -> Auto', async () => {
    const toggle = page.locator('[data-testid="theme-toggle"]');

    // Starts at Auto
    await expect(toggle).toHaveAttribute('data-theme-mode', 'auto');

    // Click: Auto -> Light
    await toggle.click();
    await expect(toggle).toHaveAttribute('data-theme-mode', 'light');
    await expect(toggle).toContainText('Light');

    // Click: Light -> Dark
    await toggle.click();
    await expect(toggle).toHaveAttribute('data-theme-mode', 'dark');
    await expect(toggle).toContainText('Dark');

    // Click: Dark -> Auto
    await toggle.click();
    await expect(toggle).toHaveAttribute('data-theme-mode', 'auto');
    await expect(toggle).toContainText('Auto');
  });

  test('persists selected mode across page reloads', async () => {
    const toggle = page.locator('[data-testid="theme-toggle"]');

    // Switch to Light
    await toggle.click();
    await expect(toggle).toHaveAttribute('data-theme-mode', 'light');

    // Reload page
    await page.reload();
    await page.waitForSelector('[data-testid="theme-toggle"]');
    await expect(page.locator('[data-testid="theme-toggle"]')).toHaveAttribute('data-theme-mode', 'light');
  });

  test('Light mode applies light class to html element', async () => {
    const toggle = page.locator('[data-testid="theme-toggle"]');
    await toggle.click(); // Auto -> Light

    const htmlClass = await page.evaluate(() => document.documentElement.className);
    expect(htmlClass).toContain('light');
    expect(htmlClass).not.toContain('dark');
  });

  test('Dark mode applies dark class to html element', async () => {
    const toggle = page.locator('[data-testid="theme-toggle"]');
    await toggle.click(); // Auto -> Light
    await toggle.click(); // Light -> Dark

    const htmlClass = await page.evaluate(() => document.documentElement.className);
    expect(htmlClass).toContain('dark');
    expect(htmlClass).not.toContain('light');
  });

  test('Auto mode respects emulated dark color scheme', async () => {
    const context = await browser.newContext({
      colorScheme: 'dark',
    });
    const darkPage = await context.newPage();
    await darkPage.goto(BASE_URL);
    await darkPage.evaluate(() => localStorage.clear());
    await darkPage.reload();
    await darkPage.waitForSelector('[data-testid="theme-toggle"]');

    // Should be Auto mode but resolved to dark
    const toggle = darkPage.locator('[data-testid="theme-toggle"]');
    await expect(toggle).toHaveAttribute('data-theme-mode', 'auto');

    const htmlClass = await darkPage.evaluate(() => document.documentElement.className);
    expect(htmlClass).toContain('dark');

    await context.close();
  });

  test('Auto mode respects emulated light color scheme', async () => {
    const context = await browser.newContext({
      colorScheme: 'light',
    });
    const lightPage = await context.newPage();
    await lightPage.goto(BASE_URL);
    await lightPage.evaluate(() => localStorage.clear());
    await lightPage.reload();
    await lightPage.waitForSelector('[data-testid="theme-toggle"]');

    const toggle = lightPage.locator('[data-testid="theme-toggle"]');
    await expect(toggle).toHaveAttribute('data-theme-mode', 'auto');

    const htmlClass = await lightPage.evaluate(() => document.documentElement.className);
    expect(htmlClass).toContain('light');

    await context.close();
  });

  test('no console errors on page load', async () => {
    const errors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.reload();
    await page.waitForSelector('[data-testid="theme-toggle"]');

    // Filter out expected errors from missing backend (proxy errors, Axios errors)
    const unexpectedErrors = errors.filter(e =>
      !e.includes('/api/') &&
      !e.includes('AxiosError') &&
      !e.includes('500 (Internal Server Error)')
    );
    expect(unexpectedErrors).toHaveLength(0);
  });

  test('takes screenshot in each mode for visual verification', async () => {
    const toggle = page.locator('[data-testid="theme-toggle"]');

    // Auto mode screenshot
    await page.screenshot({ path: 'tests/screenshots/theme-auto.png', fullPage: true });

    // Light mode
    await toggle.click();
    await page.screenshot({ path: 'tests/screenshots/theme-light.png', fullPage: true });

    // Dark mode
    await toggle.click();
    await page.screenshot({ path: 'tests/screenshots/theme-dark.png', fullPage: true });
  });
});
