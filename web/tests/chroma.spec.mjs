import { test, expect } from '@playwright/test';

async function signIn(page) {
  await page.goto('/login');
  await page.getByLabel('Username').fill('demo');
  await page.getByLabel('Password').fill('recon-demo');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('#view-home')).toBeVisible();
  await expect(page.locator('#home-content')).toBeVisible();
}

async function mockProfiles(page, initialCount, { mockIndex = true } = {}) {
  const state = {
    rows: Array.from({ length: initialCount }, (_, i) => ({
      ID: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`,
      Domain: `host-${String(i + 1).padStart(3, '0')}.example.test`,
      Schedule: 'every day at 09:00', IsScanning: false, LastScanStatus: '',
    })),
    pageRequests: 0,
    indexRequests: 0,
    delayPage: null,
  };
  await page.route('**/api/profiles/index', route => {
    state.indexRequests++;
    if (!mockIndex) return route.fallback();
    return route.fulfill({ json: state.rows.map(row => ({ id: row.ID, domain: row.Domain })) });
  });
  await page.route('**/api/profiles?**', async route => {
    state.pageRequests++;
    const q = new URL(route.request().url()).searchParams;
    const size = Number(q.get('size') || 25);
    const totalPages = Math.max(1, Math.ceil(state.rows.length / size));
    const pageNumber = Math.min(Number(q.get('page') || 1), totalPages);
    const sorted = [...state.rows].sort((a, b) => a.Domain.localeCompare(b.Domain));
    if (state.delayPage === pageNumber) await new Promise(resolve => setTimeout(resolve, 250));
    return route.fulfill({ json: {
      data: sorted.slice((pageNumber - 1) * size, pageNumber * size),
      page: { page: pageNumber, size, total_rows: state.rows.length, total_pages: totalPages, sort: 'domain-asc' },
    } });
  });
  return state;
}

test('login has a persistent theme control and accessible sign-in form', async ({ page }) => {
  await page.goto('/login');
  const theme = page.locator('#login-theme-toggle');
  await expect(theme).toBeVisible();
  await theme.click();
  const selected = await page.locator('html').getAttribute('data-theme');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', selected);
  await expect(page.getByLabel('Username')).toBeVisible();
  await expect(page.getByLabel('Password')).toBeVisible();
});

test('Home handles empty and failed overview states', async ({ page }) => {
  await page.route('**/api/profiles/index', route => route.fulfill({ status: 200, json: [] }));
  await page.goto('/login');
  await page.getByLabel('Username').fill('demo');
  await page.getByLabel('Password').fill('recon-demo');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('#home-empty')).toBeVisible();
  await page.unroute('**/api/profiles/index');
  await page.route('**/overview', route => route.fulfill({ status: 503, body: 'Mock overview failure' }));
  await page.reload();
  await expect(page.locator('#home-error')).toBeVisible();
  await expect(page.locator('#home-content')).toBeHidden();
});

test('Home, Profiles, Findings and node details retain their actions', async ({ page }) => {
  await signIn(page);
  await expect(page.locator('#home-asset-total')).not.toHaveText('0');
  await expect(page.locator('#home-response-track')).toHaveAttribute('aria-label', /assets have an HTTP response/);
  await page.locator('#nav-btn-theme').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', /light|dark/);

  await page.getByRole('button', { name: 'Profiles', exact: true }).click();
  await expect(page.locator('#view-targets')).toBeVisible();
  await expect(page.locator('#view-home')).toBeHidden();
  await expect(page.locator('#targets-tbody tr')).not.toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Run scan' }).first()).toBeVisible();
  await page.getByRole('button', { name: /Edit schedule for/ }).first().click();
  await expect(page.locator('#modal-edit-schedule')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#modal-edit-schedule')).toBeHidden();

  await page.getByRole('button', { name: 'Findings', exact: true }).click();
  await expect(page.locator('#view-discoveries')).toBeVisible();
  await expect(page.locator('#view-targets')).toBeHidden();
  await expect(page.locator('#tbody-subs tr')).not.toHaveCount(0);
  await page.locator('#select-size').selectOption('25');
  await expect(page.locator('#pager-position')).toContainText('1');
  await page.locator('#filter-btn-vuln-critical').click();
  await expect(page.locator('#filter-btn-vuln-critical')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#filter-btn-vuln-critical').click();
  await page.locator('#tbody-subs [data-action="open-node"]').first().click();
  await expect(page.locator('#sub-dashboard')).toBeVisible();
  await page.getByRole('button', { name: 'Back to nodes' }).click();
  await expect(page.locator('#table-subs')).toBeVisible();
});

test('WAF technologies are unique on Home and explicit in node details', async ({ page }) => {
  await signIn(page);
  await expect(page.locator('#home-waf-list .chroma-waf-chip')).toHaveCount(2);
  await expect(page.locator('#home-waf-list')).toContainText('Cloudflare');
  await expect(page.locator('#home-waf-list')).toContainText('Unknown WAF');
  await page.getByRole('button', { name: 'Findings', exact: true }).click();
  await page.locator('#tbody-subs tr').filter({ hasText: /app\.acme\.example\.com/i })
    .locator('[data-action="open-node"]').click();
  await expect(page.locator('#sub-dash-ip')).toHaveText('IP: 203.0.113.10  |  Cloudflare detected');
  await page.getByRole('button', { name: 'Back to nodes' }).click();
  await page.locator('#tbody-subs tr').filter({ hasText: /admin\.acme\.example\.com/i })
    .locator('[data-action="open-node"]').click();
  await expect(page.locator('#sub-dash-ip')).toHaveText('IP: 203.0.113.12  |  No WAF detected');
});

test('credential views show engine and limit SecretHound details to a node', async ({ page }) => {
  await signIn(page);
  const rendered = await page.evaluate(() => {
    const finding = {
      SecretType: 'aws', SecretValue: 'AKIA-test',
      SourceURL: 'https://a.example.com/app.js', Engine: 'SecretHound',
      Risk: 'high', Occurrences: 2, Description: '<img src=x onerror=alert(1)>',
      Context: ['<script>alert(1)</script>'],
    };
    const general = buildSecretRow(finding);
    const node = buildSecretRow(finding, true);
    const generalMobile = buildSecretCard(finding);
    const nodeMobile = buildSecretCard(finding, true);
    return {
      generalCells: general.cells.length,
      generalText: general.textContent,
      nodeCells: node.cells.length,
      nodeText: node.textContent,
      nodeDetails: node.querySelector('details')?.textContent,
      injectedElements: node.querySelectorAll('img, script').length + nodeMobile.querySelectorAll('img, script').length,
      generalMobileText: generalMobile.textContent,
      nodeMobileText: nodeMobile.textContent,
    };
  });
  expect(rendered.generalCells).toBe(4);
  expect(rendered.generalText).toContain('SecretHound');
  expect(rendered.generalText).not.toContain('Risk:');
  expect(rendered.nodeCells).toBe(5);
  expect(rendered.nodeText).toContain('Risk: high');
  expect(rendered.nodeText).toContain('Occurrences: 2');
  expect(rendered.nodeDetails).toContain('<img src=x onerror=alert(1)>');
  expect(rendered.injectedElements).toBe(0);
  expect(rendered.generalMobileText).not.toContain('high');
  expect(rendered.nodeMobileText).toContain('high');
  expect(rendered.nodeMobileText).toContain('<script>alert(1)</script>');
});

test('Profiles spacing, schedule labels, short IDs and filled Delete work in both themes', async ({ page }) => {
  await signIn(page);
  await page.locator('#nav-btn-profiles').click();
  const row = page.locator('#targets-tbody tr').first();
  const id = row.locator('td').first();
  await expect(id).toHaveText(/^[a-f0-9]{6}$/i);
  const schedule = row.locator('[id^="schedule-text-"]');
  const raw = await schedule.getAttribute('data-schedule');
  const display = await page.evaluate(value => scheduleLabel(value), raw);
  await expect(schedule).toHaveText(display);
  expect(await page.evaluate(() => scheduleLabel('@every 8760h'))).toBe('Every 365 days (interval)');
  const field = await page.locator('#input-domain').boundingBox();
  const scheduleControl = await page.locator('.chroma-schedule-control').boundingBox();
  const add = await page.getByRole('button', { name: 'Add profile' }).boundingBox();
  expect(scheduleControl.x - (field.x + field.width)).toBeGreaterThanOrEqual(12);
  expect(add.x - (scheduleControl.x + scheduleControl.width)).toBeGreaterThanOrEqual(12);
  const label = await schedule.boundingBox();
  const edit = await row.locator('[data-action="edit-schedule"]').boundingBox();
  expect(edit.x - (label.x + label.width)).toBeGreaterThanOrEqual(8);
  for (const theme of ['dark', 'light']) {
    await page.evaluate(value => { document.documentElement.dataset.theme = value; }, theme);
    const radii = await page.evaluate(() => {
      const radius = selector => getComputedStyle(document.querySelector(selector)).borderTopLeftRadius;
      return {
        standard: radius('#targets-tbody [data-action="edit-schedule"]'),
        profiles: radius('#profiles-pager [data-profile-pager="next"]'),
        findings: radius('#pager [data-pager="next"]'),
      };
    });
    expect(radii.profiles).toBe(radii.standard);
    expect(radii.findings).toBe(radii.standard);
    const colors = await row.locator('[data-action="delete"]').evaluate(button => ({
      button: getComputedStyle(button).backgroundColor,
      row: getComputedStyle(button.closest('tr')).backgroundColor,
    }));
    expect(colors.button).not.toBe('rgba(0, 0, 0, 0)');
    expect(colors.button).not.toBe(colors.row);
  }
  await row.locator('[data-action="edit-schedule"]').click();
  await expect(page.locator('#modal-edit-schedule')).toBeVisible();
  if (raw.startsWith('@every')) await expect(page.locator('#edit-schedule-hint')).toBeVisible();
  else await expect(page.locator('#edit-schedule-hint')).toBeHidden();
});

test('Findings panels and node-table columns have breathing room', async ({ page }) => {
  await signIn(page);
  await page.locator('#nav-btn-findings').click();
  await expect(page.locator('#table-subs')).toBeVisible();
  const profile = await page.locator('#view-discoveries > .chroma-controls-panel').boundingBox();
  const filters = await page.locator('#controls-bar').boundingBox();
  const results = await page.locator('.chroma-finding-panel').boundingBox();
  expect(filters.y - (profile.y + profile.height)).toBeGreaterThanOrEqual(12);
  expect(results.y - (filters.y + filters.height)).toBeGreaterThanOrEqual(12);
  const statusHeader = await page.locator('.chroma-node-table th').nth(2).boundingBox();
  const statusCell = await page.locator('#tbody-subs tr').first().locator('td').nth(2).boundingBox();
  expect(Math.abs((statusHeader.x + statusHeader.width / 2) - (statusCell.x + statusCell.width / 2))).toBeLessThanOrEqual(1);
  const openLink = await page.locator('#tbody-subs .chroma-node-open').first().boundingBox();
  expect(openLink.width).toBeLessThanOrEqual(32);
});

test('profile creation, scan request, and deletion remain usable on the disposable fixture', async ({ page, browserName }) => {
  await signIn(page);
  await page.locator('#nav-btn-profiles').click();
  const domain = `ui-${Date.now()}-${browserName}.example.invalid`;
  await page.locator('#input-domain').fill(domain);
  await page.getByRole('button', { name: 'Add profile' }).click();
  const row = page.locator('#targets-tbody tr').filter({ hasText: domain });
  await expect(row).toBeVisible();
  let scanRequested = false;
  await page.route('**/api/profiles/*/scan', route => {
    scanRequested = true;
    return route.fulfill({ status: 200, json: {} });
  });
  page.on('dialog', dialog => dialog.accept());
  await row.locator('[data-action="scan"]').click();
  expect(scanRequested).toBe(true);
  await row.locator('[data-action="delete"]').click();
  await expect(row).toHaveCount(0);
});

test('Profiles pager navigates beyond 250, preserves URL context, and changes page size', async ({ page }) => {
  await signIn(page);
  const state = await mockProfiles(page, 251, { mockIndex: false });
  await page.goto('/?view=profiles&size=50');
  await expect(page.locator('#targets-tbody tr')).toHaveCount(25);
  await expect(page.locator('#target-count')).toHaveText('251 profiles');
  await expect(page.locator('#profiles-pager-summary')).toHaveText('1–25 of 251');
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 1 / 11');
  const pagerButton = await page.locator('#profiles-pager [data-profile-pager="next"]').boundingBox();
  expect(pagerButton.height).toBeLessThanOrEqual(32);
  await expect(page.locator('#profiles-pager [data-profile-pager="first"]')).toBeDisabled();
  await expect(page.locator('#profiles-pager [data-profile-pager="prev"]')).toBeDisabled();
  const indexRequests = state.indexRequests;
  await page.locator('#profiles-pager [data-profile-pager="next"]').click();
  await expect(page.locator('#profiles-pager-summary')).toHaveText('26–50 of 251');
  await expect(page.locator('#targets-tbody')).toContainText('host-026.example.test');
  await expect.poll(() => new URL(page.url()).searchParams.get('profiles_page')).toBe('2');
  expect(new URL(page.url()).searchParams.get('size')).toBe('50');
  expect(state.indexRequests).toBe(indexRequests);
  await page.reload();
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 2 / 11');
  await page.locator('#profiles-page-size').selectOption('50');
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 1 / 6');
  await expect(page.locator('#targets-tbody')).toContainText('host-026.example.test');
  expect(new URL(page.url()).searchParams.get('profiles_size')).toBe('50');
  await page.locator('#profiles-pager [data-profile-pager="last"]').click();
  await expect(page.locator('#profiles-pager-summary')).toHaveText('251–251 of 251');
  await expect(page.locator('#profiles-pager [data-profile-pager="next"]')).toBeDisabled();
  await expect(page.locator('#profiles-pager [data-profile-pager="last"]')).toBeDisabled();
  await page.locator('#nav-btn-findings').click();
  await page.locator('#nav-btn-profiles').click();
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 6 / 6');
  expect(state.pageRequests).toBeGreaterThanOrEqual(4);
});

test('Profiles creation reveals the new row and deletion clamps the last page', async ({ page }) => {
  await signIn(page);
  const state = await mockProfiles(page, 26);
  await page.route('**/api/profiles', route => {
    if (route.request().method() !== 'POST') return route.continue();
    const body = route.request().postDataJSON();
    const created = {
      ID: '00000000-0000-4000-8000-000000000027',
      Domain: body.domain, Schedule: body.schedule, IsScanning: false, LastScanStatus: '',
    };
    state.rows.push(created);
    return route.fulfill({ status: 201, json: created });
  });
  await page.route('**/api/profiles/*', route => {
    if (route.request().method() !== 'DELETE') return route.fallback();
    const id = route.request().url().split('/').pop();
    state.rows = state.rows.filter(row => row.ID !== id);
    return route.fulfill({ status: 204, body: '' });
  });
  await page.goto('/?view=profiles');
  await page.locator('#input-domain').fill('host-026a.example.test');
  await page.getByRole('button', { name: 'Add profile' }).click();
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 2 / 2');
  const created = page.locator('#targets-tbody tr').filter({ hasText: 'host-026a.example.test' });
  await expect(created).toBeVisible();
  await expect(page.locator('#select-profile option')).toHaveCount(27);
  await expect(page.locator('#select-home-profile option')).toHaveCount(27);
  page.on('dialog', dialog => dialog.accept());
  await created.locator('[data-action="delete"]').click();
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 2 / 2');
  const last = page.locator('#targets-tbody tr').filter({ hasText: 'host-026.example.test' });
  await last.locator('[data-action="delete"]').click();
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 1 / 1');
  await expect(page.locator('#targets-tbody tr')).toHaveCount(25);
});

test('Profiles pager handles empty, single-page, and mobile-card layouts', async ({ page }) => {
  await signIn(page);
  const state = await mockProfiles(page, 1);
  await page.goto('/?view=profiles');
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 1 / 1');
  await expect(page.locator('#profiles-pager [data-profile-pager="next"]')).toBeDisabled();
  const requests = state.pageRequests;
  await page.setViewportSize({ width: 320, height: 568 });
  await expect(page.locator('#targets-tbody tr')).toHaveCount(0);
  await expect(page.locator('#targets-mobile li')).toHaveCount(1);
  await expect(page.locator('#profiles-pager')).toBeVisible();
  expect(state.pageRequests).toBe(requests);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
  state.rows = [];
  await page.reload();
  await expect(page.locator('#targets-empty')).toBeVisible();
  await expect(page.locator('#profiles-pager')).toBeHidden();
  await expect(page.locator('#target-count')).toHaveText('0 profiles');
});

test('a late Profiles page response cannot replace the newer page', async ({ page }) => {
  await signIn(page);
  const state = await mockProfiles(page, 75);
  await page.goto('/?view=profiles');
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 1 / 3');
  state.delayPage = 2;
  await page.evaluate(() => {
    goToProfilesPage(2);
    viewState.profilesPage = 3;
    loadProfilesPage();
  });
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 3 / 3');
  await expect(page.locator('#targets-tbody')).toContainText('host-051.example.test');
  await page.waitForTimeout(300);
  await expect(page.locator('#profiles-pager-position')).toHaveText('Page 3 / 3');
  await expect(page.locator('#targets-tbody')).not.toContainText('host-026.example.test');
});

test('severity breakdown opens after hover, reuses cache, and hides on leave and Escape', async ({ page }) => {
  await signIn(page);
  await page.locator('#nav-btn-findings').click();
  const badge = page.locator('#tbody-subs [data-action="show-severity-summary"]').first();
  const summaryRequests = [];
  page.on('request', request => {
    if (request.url().includes('/vulnerabilities/severity-summary')) summaryRequests.push(request.url());
  });
  await badge.hover();
  await page.waitForTimeout(100);
  await expect(page.locator('#severity-tooltip')).toBeHidden();
  await expect(page.locator('#severity-tooltip')).toBeVisible();
  await expect(page.locator('#severity-tooltip')).toContainText(/Critical|High|Medium|Low|Info/);
  await page.mouse.move(0, 0);
  await expect(page.locator('#severity-tooltip')).toBeHidden();
  await badge.focus();
  await expect(page.locator('#severity-tooltip')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('#severity-tooltip')).toBeHidden();
  await badge.hover();
  await expect(page.locator('#severity-tooltip')).toBeVisible();
  expect(summaryRequests.length).toBe(1);
});

test('touch-sized Findings keep actions visible and dismiss the breakdown on scroll', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  await page.locator('#nav-btn-findings').click();
  const card = page.locator('#subs-mobile li').filter({ hasText: 'app.acme.example.com' }).first();
  await expect(card.getByRole('button', { name: 'Open node' })).toBeVisible();
  await card.locator('[data-action="show-severity-summary"]').click();
  await expect(page.locator('#severity-tooltip')).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new Event('scroll')));
  await expect(page.locator('#severity-tooltip')).toBeHidden();
});

test('Findings filter and pager keep the selected page visible', async ({ page }) => {
  await signIn(page);
  await page.route('**/subdomains?**', async route => {
    const response = await route.fetch();
    const body = await response.json();
    const params = new URL(route.request().url()).searchParams;
    const pageNumber = Number(params.get('page') || 1);
    const size = Number(params.get('size') || 25);
    const sample = body.data[0];
    body.data = Array.from({ length: size }, (_, i) => {
      const n = (pageNumber - 1) * size + i + 1;
      return { ...sample, id: n, domain: `node-${n}.acme.example.com`, host: `node-${n}.acme.example.com` };
    });
    body.page = { ...body.page, page: pageNumber, size, total_rows: 50, total_pages: 2 };
    await route.fulfill({ response, json: body });
  });
  await page.locator('#nav-btn-findings').click();
  await page.locator('#select-size').selectOption('25');
  await expect(page.locator('#pager-position')).toHaveText('Page 1 / 2');
  await page.locator('#pager [data-pager="next"]').click();
  await expect(page.locator('#pager-position')).toHaveText('Page 2 / 2');
  await expect(page.locator('#tbody-subs')).toContainText('node-26.acme.example.com');
});

for (const viewport of [
  { width: 320, height: 568 }, { width: 390, height: 844 },
  { width: 768, height: 1024 }, { width: 1024, height: 768 },
  { width: 1440, height: 900 }, { width: 812, height: 375 },
]) {
  test(`responsive layout has no page overflow at ${viewport.width}×${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await signIn(page);
    for (const view of ['home', 'profiles', 'findings']) {
      await page.locator(`#nav-btn-${view}`).click();
      if (view === 'findings') await expect(page.locator('#table-subs')).toBeVisible();
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      expect(overflow).toBeLessThanOrEqual(1);
    }
    if (viewport.width <= 640) {
      for (const view of ['home', 'profiles', 'findings']) {
        await expect(page.locator(`#nav-btn-${view}`)).toBeVisible();
      }
      await expect(page.locator('#targets-tbody tr')).toHaveCount(0);
      await expect(page.locator('#targets-mobile li')).not.toHaveCount(0);
      await page.locator('#nav-btn-profiles').click();
      await expect(page.locator('#targets-mobile [data-action="scan"]')).toBeVisible();
      await page.locator('#nav-btn-findings').click();
      await expect(page.locator('#tbody-subs tr')).toHaveCount(0);
      await expect(page.locator('#subs-mobile li')).not.toHaveCount(0);
      await page.locator('#mobile-filter-summary').click();
      await expect(page.locator('#filter-btn-updated')).toBeVisible();
    }
  });
}

test('500-row breakpoint switch renders one representation without another fetch', async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await signIn(page);
  let requests = 0;
  await page.route('**/subdomains?**', async route => {
    requests++;
    const response = await route.fetch();
    const body = await response.json();
    const sample = body.data[0];
    body.data = Array.from({ length: 500 }, (_, i) => ({
      ...sample, id: i + 1, domain: `node-${i}.acme.example.com`, host: `node-${i}.acme.example.com`,
    }));
    body.page = { ...body.page, page: 1, size: 500, total_rows: 500, total_pages: 1 };
    await route.fulfill({ response, json: body });
  });
  await page.locator('#nav-btn-findings').click();
  await page.locator('#select-size').selectOption('500');
  await expect(page.locator('#tbody-subs tr')).toHaveCount(500);
  const before = requests;
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.locator('#tbody-subs tr')).toHaveCount(0);
  await expect(page.locator('#subs-mobile li')).toHaveCount(500);
  expect(requests).toBe(before);
  await page.setViewportSize({ width: 1024, height: 768 });
  await expect(page.locator('#subs-mobile li')).toHaveCount(0);
  await expect(page.locator('#tbody-subs tr')).toHaveCount(500);
  expect(requests).toBe(before);
});
