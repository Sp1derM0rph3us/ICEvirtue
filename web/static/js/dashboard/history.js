import { apiJSON } from './api.js';
import { overviewUTC } from './views.js';

// History is loaded on demand and paginated independently of the findings view.
export function mountHistory() {
  const dialog = document.getElementById('run-history');
  const list = dialog.querySelector('[data-history-list]');
  const detail = dialog.querySelector('[data-history-detail]');
  let profile, page = 1, pages = 1;
  async function load() {
    list.textContent = 'Loading run history…';
    detail.replaceChildren();
    try {
      const result = await apiJSON(`/api/profiles/${profile}/runs?page=${page}&size=25`);
      pages = result.page.total_pages;
      page = result.page.page;
      list.replaceChildren();
      if (!result.data.length) list.textContent = 'No recorded runs. Completed history is retained for 30 days.';
      for (const run of result.data) {
        const button = document.createElement('button');
        button.className = 'chroma-button-secondary';
        button.textContent = `${overviewUTC(run.started_at)} · ${run.status} · ${run.source} · revision ${run.revision}`;
        button.addEventListener('click', async () => {
          try {
            const data = await apiJSON(`/api/runs/${run.id}`);
            const rows = [data.run.summary, ...data.stages.map(s => `${s.name}: ${s.status} · ${s.output_count} results · ${s.persisted_count} new findings`), ...data.tools.map(t => `${t.name} [${t.scope || "result"}]: ${t.status} · ${t.output_count} results${t.summary ? ' · '+t.summary : ''}`)];
            detail.textContent = rows.join('\n');
          } catch (e) { detail.textContent = e.message; }
        });
        list.append(button);
      }
      dialog.querySelector('[data-history-page]').textContent = `Page ${page} of ${pages}`;
      dialog.querySelector('[data-history-prev]').disabled = page <= 1;
      dialog.querySelector('[data-history-next]').disabled = page >= pages;
    } catch (e) { list.textContent = e.message; }
  }
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-run-history]');
    if (!button) return;
    profile = button.dataset.runHistory; page = 1; dialog.showModal(); load();
  });
  dialog.querySelector('[data-history-close]').addEventListener('click', () => dialog.close());
  dialog.querySelector('[data-history-prev]').addEventListener('click', () => { page--; load(); });
  dialog.querySelector('[data-history-next]').addEventListener('click', () => { page++; load(); });
}
