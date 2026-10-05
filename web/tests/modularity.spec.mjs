import { test, expect } from '@playwright/test';

async function login(page) {
  await page.goto('/login');
  await page.getByLabel('Username').fill('demo');
  await page.getByLabel('Password', { exact: true }).fill('recon-demo');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('#home-content')).toBeVisible();
}

test('external modules respect CSP and expose run and worker diagnostics', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page);
  const response = await page.request.get('/');
  expect(response.headers()['content-security-policy']).toContain("script-src 'self';");
  await expect(page.locator('script:not([src])')).toHaveCount(0);
  expect(await page.locator('[onclick],[onchange],[oninput]').count()).toBe(0);
  await page.route('**/api/profiles/*/runs?*', route => route.fulfill({ json: {
    data: [{id:'test-run', started_at:'2026-10-01T09:00:00Z',status:'interrupted',source:'manual',revision:7}],
    page: {page:1,total_pages:1,total_rows:1,size:25},
  }}));
  await page.route('**/api/runs/test-run', route => route.fulfill({ json: {
    run: {summary:'interrupted: worker lease expired'},
    stages:[{name:'discovery',status:'completed',output_count:2,persisted_count:2}],
    tools:[{name:'subfinder',scope:'result',status:'completed',output_count:2,summary:''}],
  }}));
  await page.getByRole('button', { name:'Profiles',exact:true }).click();
  await page.getByRole('button', { name:'Run history',exact:true }).first().click();
  await expect(page.locator('#run-history')).toBeVisible();
  await page.locator('#run-history [data-history-list] button').click();
  await expect(page.locator('[data-history-detail]')).toContainText('worker lease expired');
  await expect(page.locator('[data-history-detail]')).toContainText('2 new findings');
  await page.locator('[data-history-close]').click();
  await page.route('**/api/admin/workers', route => route.fulfill({json:{
    workers:[{id:'worker-one',last_seen:1790845200,online:true}],queue_depth:3,oldest_queued_seconds:42,
  }}));
  await page.goto('/settings/admin');
  await expect(page.locator('#worker-status')).toContainText('3 queued · oldest queued 42s');
  await expect(page.locator('#worker-status')).toContainText('worker-one');
  expect(errors).toEqual([]);
});

test('a replay-window reset refreshes displayed data', async ({page}) => {
  let resets = 0, profiles = 0;
  page.on('request',request=>{if(request.url().includes('/api/profiles/index')) profiles++;});
  await page.route('**/api/events',async route=>{
    await new Promise(resolve=>setTimeout(resolve,500));
    resets++;
    await route.fulfill({status:200,contentType:'text/event-stream',body:'id: 99\ndata: {"type":"stream_reset"}\n\n'});
  });
  await login(page);
  await expect.poll(()=>resets).toBeGreaterThan(0);
  await expect.poll(()=>profiles).toBeGreaterThan(1);
  await expect(page.locator('#home-content')).toBeVisible();
});
