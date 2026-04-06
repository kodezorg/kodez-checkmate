/**
 * wf-toast.js — Workflow completion SSE toast
 *
 * Self-contained: injects its own CSS, creates the DOM element, opens
 * the SSE connection and shows a toast on every "workflow_complete" event.
 * Works on any authenticated page — just include this script.
 */
(function () {
  // ── Inject CSS ────────────────────────────────────────────────────────
  const style = document.createElement('style');
  style.textContent = `
    #wf-toast {
      position: fixed;
      top: 20px;
      left: 50%;
      transform: translateX(-50%) translateY(-140%);
      z-index: 9999;
      display: flex;
      align-items: flex-start;
      gap: 12px;
      background: #0f172a;
      border: 1px solid rgba(16,185,129,.45);
      border-radius: 12px;
      padding: 14px 18px;
      box-shadow: 0 12px 36px rgba(0,0,0,.35), 0 0 0 1px rgba(16,185,129,.15);
      min-width: 320px;
      max-width: min(520px, calc(100vw - 32px));
      transition: transform .35s cubic-bezier(.34,1.56,.64,1), opacity .3s;
      opacity: 0;
      pointer-events: none;
      font-family: 'Public Sans', system-ui, sans-serif;
    }
    #wf-toast.show {
      transform: translateX(-50%) translateY(0);
      opacity: 1;
      pointer-events: auto;
    }
    .wf-toast-icon {
      font-size: 22px;
      line-height: 1;
      flex-shrink: 0;
      margin-top: 1px;
    }
    .wf-toast-body { flex: 1; min-width: 0; }
    .wf-toast-title {
      font-size: 13px;
      font-weight: 700;
      color: #f1f5f9;
      letter-spacing: -.01em;
    }
    .wf-toast-meta {
      font-size: 11px;
      color: #94a3b8;
      font-family: 'IBM Plex Mono', monospace;
      margin-top: 3px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .wf-toast-link {
      display: inline-block;
      margin-top: 7px;
      font-size: 11px;
      font-weight: 700;
      color: #10b981;
      text-decoration: none;
      font-family: 'IBM Plex Mono', monospace;
    }
    .wf-toast-link:hover { text-decoration: underline; }
    .wf-toast-close {
      background: none;
      border: none;
      color: #64748b;
      cursor: pointer;
      font-size: 16px;
      line-height: 1;
      padding: 0 0 0 6px;
      flex-shrink: 0;
      align-self: flex-start;
    }
    .wf-toast-close:hover { color: #e2e8f0; }
  `;
  document.head.appendChild(style);

  // ── Inject DOM ────────────────────────────────────────────────────────
  const toastEl = document.createElement('div');
  toastEl.id = 'wf-toast';
  toastEl.setAttribute('role', 'alert');
  toastEl.setAttribute('aria-live', 'assertive');
  toastEl.innerHTML = `
    <div class="wf-toast-icon">✅</div>
    <div class="wf-toast-body">
      <div class="wf-toast-title" id="wf-toast-title">Workflow completed</div>
      <div class="wf-toast-meta" id="wf-toast-meta"></div>
      <a id="wf-toast-link" class="wf-toast-link" href="#" target="_blank"
         rel="noopener noreferrer" style="display:none">View run on GitHub →</a>
    </div>
    <button class="wf-toast-close" id="wf-toast-close" type="button" aria-label="Dismiss">✕</button>
  `;
  document.body.appendChild(toastEl);

  // ── Toast logic ───────────────────────────────────────────────────────
  const toastTitle = document.getElementById('wf-toast-title');
  const toastMeta  = document.getElementById('wf-toast-meta');
  const toastLink  = document.getElementById('wf-toast-link');
  const toastClose = document.getElementById('wf-toast-close');
  let hideTimer = null;

  function showToast(data) {
    toastTitle.textContent = `✅ Workflow "${data.workflowName}" completed`;
    toastMeta.textContent  = `Run #${data.runNumber} · ${data.branch} · ${data.sha}`;
    if (data.runUrl) {
      toastLink.href = data.runUrl;
      toastLink.style.display = 'inline-block';
    } else {
      toastLink.style.display = 'none';
    }
    toastEl.classList.add('show');
    clearTimeout(hideTimer);
    hideTimer = setTimeout(dismissToast, 12000);
  }

  function dismissToast() {
    toastEl.classList.remove('show');
  }

  toastClose.addEventListener('click', dismissToast);

  // ── SSE connection ────────────────────────────────────────────────────
  // Track a pending fallback-sync timer so we can cancel it when the
  // dedicated `reports_imported` event arrives first.
  let pendingSyncTimer = null;

  function cancelPendingSync() {
    if (pendingSyncTimer !== null) {
      clearTimeout(pendingSyncTimer);
      pendingSyncTimer = null;
    }
  }

  function connect() {
    const es = new EventSource('/api/events');

    // `workflow_complete` fires immediately when GitHub webhook arrives.
    // Show the toast right away, then schedule a fallback data refresh in
    // case the server-side `reports_imported` event never arrives (e.g.
    // GITHUB_WEBHOOK_TOKEN is not configured).
    es.addEventListener('workflow_complete', (e) => {
      try {
        const data = JSON.parse(e.data);
        showToast(data);
        // Cancel any running poll — webhook is working, SSE path will handle the refresh.
        if (typeof window.stopWorkflowPolling === 'function') window.stopWorkflowPolling();
        // Fallback: if reports_imported doesn't fire within 8 s, sync manually.
        cancelPendingSync();
        pendingSyncTimer = setTimeout(() => {
          pendingSyncTimer = null;
          if (typeof window.syncReportsAndRefresh === 'function') {
            window.syncReportsAndRefresh();
          } else if (typeof window.loadScans === 'function') {
            window.loadScans();
          }
        }, 8000);
      } catch { /* ignore malformed event */ }
    });

    // `reports_imported` fires after the server has already upserted the
    // reports into the DB.  Just reload scans — no GitHub API call needed.
    es.addEventListener('reports_imported', (e) => {
      try {
        cancelPendingSync(); // server handled the import; cancel fallback
        if (typeof window.stopWorkflowPolling === 'function') window.stopWorkflowPolling();
        if (typeof window.loadScans === 'function') {
          window.loadScans();
        }
        if (typeof window.loadRuns === 'function') {
          window.loadRuns();
        }
      } catch { /* ignore */ }
    });

    es.onerror = () => {
      es.close();
      setTimeout(connect, 5000); // reconnect after back-off
    };
  }

  connect();
})();
