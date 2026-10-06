import { test, expect } from '@playwright/test';

async function openFixture(page) {
  await page.goto('/login');
  await page.getByLabel('Username').fill('demo');
  await page.getByLabel('Password', {exact:true}).fill('recon-demo');
  await page.getByRole('button', {name:'Sign in',exact:true}).click();
  await expect(page.locator('#home-content')).toBeVisible();
  const profiles = await (await page.request.get('/api/profiles/index')).json();
  const profile = profiles[0].id;
  await page.route('**/api/profiles/*/subdomains?*',route=>route.fulfill({json:{
    data:[{id:1,domain:'x.example.com',host:'x.example.com',status_code:302,dir_count:3,confirmed_dir_count:1,unknown_dir_count:1,legacy_dir_count:1,cross_host_count:7,cross_scope_count:1,vuln_count:0,secret_count:0,first_seen:'2026-10-01',last_changed:'2026-10-05'}],
    page:{page:1,size:100,total_rows:1,total_pages:1},
  }}));
  const directoryRows = [
    {DirURL:'https://x.example.com/admin',StatusCode:200,Assessment:'confirmed',AssessmentReason:'distinct_from_missing_paths'},
    {DirURL:'https://x.example.com/private',StatusCode:302,Assessment:'unknown',AssessmentReason:'matches_missing_paths'},
    {DirURL:'https://x.example.com/legacy',StatusCode:301,Assessment:'legacy'},
  ];
  await page.route('**/api/profiles/*/directories?*',route=>{
    const assessment = new URL(route.request().url()).searchParams.get('assessment') || 'all';
    const rows = assessment === 'all' ? directoryRows : directoryRows.filter(r=>r.Assessment===assessment);
    return route.fulfill({json:{data:rows,page:{page:1,size:100,total_rows:rows.length,total_pages:1,assessment}}});
  });
  await page.route('**/api/profiles/*/redirects/summary?*',route=>route.fulfill({json:Array.from({length:6},(_,i)=>({destination_host:`y${i}.example.com`,kind:'cross_host',previously_enumerated:i===0,count:i+1}))}));
  await page.route('**/api/profiles/*/redirects?*',route=>{
    const pageNumber=Number(new URL(route.request().url()).searchParams.get('page')||1);
    return route.fulfill({json:{data:[{SourceURL:`https://x.example.com/source-${pageNumber}`,DestinationURL:'https://y.example.com/login',DestinationHost:'y.example.com',Kind:'cross_host',PreviouslyEnumerated:true,StatusCode:302,ObservedAt:'2026-10-05T09:00:00Z'}],page:{page:pageNumber,size:25,total_rows:26,total_pages:2}}});
  });
  await page.goto(`/?view=findings&profile=${profile}`);
  await expect(page.locator('#table-subs')).toBeVisible();
  return profile;
}

test('Unknown directory assessments are separate from root status and filterable',async({page})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await openFixture(page);
  const row=page.locator('#table-subs tbody tr').first();
  await expect(row.locator('td').nth(2)).toHaveText('302');
  // One consolidated chip: the total directory count (confirmed + unknown +
  // legacy). The confirmed/unknown/legacy split now lives only on the node tab.
  await expect(row).toContainText('3 directories');
  await expect(row).not.toContainText('confirmed directories');
  await expect(row).not.toContainText('Unknown directories');
  await page.locator('#filter-btn-unknown-directories').click();
  await expect(page).toHaveURL(/filter=unknown-directories/);
  await row.getByRole('button',{name:'x.example.com',exact:true}).click();
  await page.locator('#sub-tab-dirs').click();
  await expect(page.locator('#directory-assessment-filter')).toHaveValue('all');
  await expect(page.locator('#tbody-sub-dirs tr')).toHaveCount(3);
  await expect(page.locator('#tbody-sub-dirs')).toContainText('Unknown');
  await expect(page.locator('#tbody-sub-dirs')).toContainText('HTTP 302');
  await expect(page.locator('#tbody-sub-dirs')).toContainText('recorded before validation');
  await page.locator('#directory-assessment-filter').selectOption('unknown');
  await expect(page.locator('#tbody-sub-dirs tr')).toHaveCount(1);
  await expect(page).toHaveURL(/assessment=unknown/);
  await page.reload();
  await expect(page.locator('#directory-assessment-filter')).toHaveValue('unknown');
  await expect(page.locator('#tbody-sub-dirs tr')).toHaveCount(1);
  await page.locator('#directory-assessment-filter').selectOption('confirmed');
  await expect(page.locator('#tbody-sub-dirs tr')).toHaveCount(1);
  await expect(page.locator('#tbody-sub-dirs')).not.toContainText('Unknown');
  await page.setViewportSize({width:390,height:844});
  await page.locator('#directory-assessment-filter').selectOption('unknown');
  await expect(page.locator('#node-mobile')).toContainText('Unknown');
  expect(errors).toEqual([]);
});

test('the directories chip summarises redirects; full detail lives in the node tab',async({page})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await openFixture(page);
  const row=page.locator('#table-subs tbody tr').first();
  // A node that redirects off-scope turns its directories chip into an alert
  // that, on hover, summarises destinations -- the way the Findings chip
  // summarises severities. No separate redirect badge, no inline modal button.
  const chip=row.getByRole('button',{name:/directories/});
  await chip.hover();
  await expect(page.locator('#severity-tooltip')).toBeVisible();
  await expect(page.locator('#severity-tooltip-title')).toHaveText('Redirect destinations');
  await expect(page.locator('#severity-tooltip')).toContainText('y0.example.com');
  await expect(page.locator('#severity-tooltip')).toContainText('Open the node');
  await page.keyboard.press('Escape');
  await expect(page.locator('#severity-tooltip')).toBeHidden();
  await chip.focus();
  await expect(page.locator('#severity-tooltip')).toBeVisible();
  await page.keyboard.press('Escape');
  // The paginated source -> destination list is reachable only from inside the
  // node, on its Directories tab, and only when the node actually redirects.
  await row.getByRole('button',{name:'x.example.com',exact:true}).click();
  await page.locator('#sub-tab-dirs').click();
  const details=page.locator('#node-redirect-details');
  await expect(details).toBeVisible();
  await details.click();
  await expect(page.locator('#redirect-details-dialog')).toBeVisible();
  await expect(page.locator('#redirect-details-list')).toContainText('source-1');
  await page.locator('#redirect-details-next').click();
  await expect(page.locator('#redirect-details-list')).toContainText('source-2');
  await page.keyboard.press('Escape');
  await expect(page.locator('#redirect-details-dialog')).toBeHidden();
  expect(errors).toEqual([]);
});
