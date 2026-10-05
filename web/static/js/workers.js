const panel = document.getElementById('worker-status');
async function refresh() {
  try {
    const response = await fetch('/api/admin/workers', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Worker status unavailable');
    const data = await response.json();
    panel.querySelector('[data-queue]').textContent = `${data.queue_depth} queued · oldest queued ${data.oldest_queued_seconds}s`;
    const list = panel.querySelector('[data-workers]');
    list.replaceChildren();
    if (!data.workers.length) list.textContent = 'No worker heartbeats. Queued scans will wait for a worker.';
    for (const worker of data.workers) {
      const row = document.createElement('li');
      row.textContent = `${worker.id} · heartbeat ${new Date(worker.last_seen * 1000).toISOString()} · ${worker.online ? 'online' : 'offline'}`;
      list.append(row);
    }
  } catch (e) { panel.querySelector('[data-queue]').textContent = e.message; }
}
refresh();
const timer = setInterval(refresh, 10000);
window.addEventListener('pagehide', () => clearInterval(timer), {once:true});
