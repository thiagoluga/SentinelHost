/* SentinelHost panel — vanilla JS, no framework and no build step.
 *
 * The rule that runs through this file: EVERY text coming from the server enters
 * the DOM through textContent, never through innerHTML. The file paths displayed
 * here were chosen by the ATTACKER — a file named
 * `<img src=x onerror=...>.php` would turn the panel into an attack vector
 * against the site's owner. The CSP is the second barrier; this is the first.
 */
'use strict';

// ------------------------------------------------------------------- utilities

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/** Creates an element. `text` always becomes textContent. */
function el(tag, attrs = {}, text) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'dataset') Object.assign(n.dataset, v);
    else n.setAttribute(k, v);
  }
  if (text !== undefined) n.textContent = text;
  return n;
}

function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

let toastTimer;
function toast(msg, bad = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('bad', bad);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 5200);
}

async function api(path, opts = {}) {
  const resp = await fetch(path, {
    credentials: 'same-origin',
    headers: opts.body ? { 'Content-Type': 'application/json' } : {},
    ...opts,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* response with no body */ }

  if (resp.status === 401) {
    showGate();
    throw new Error('session expired');
  }
  if (!resp.ok) {
    throw new Error((data && data.error) || `HTTP ${resp.status}`);
  }
  return data;
}

function fmtDate(s) {
  if (!s || s.startsWith('0001-01-01')) return '—';
  const d = new Date(s);
  if (isNaN(d)) return '—';
  return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
}

function fmtDay(s) {
  if (!s || s.startsWith('0001-01-01')) return 'never expires';
  const d = new Date(s);
  return isNaN(d) ? '—' : d.toLocaleDateString(undefined);
}

const LEVEL_CLASS = {
  confirmed: 'b-crit', likely: 'b-serious', suspicious: 'b-warn', clean: 'b-good',
};
const LEVEL_LABEL = {
  confirmed: 'confirmed', likely: 'likely', suspicious: 'suspicious', clean: 'clean',
};

// -------------------------------------------------------------- authentication

async function bootstrap() {
  try {
    const s = await api('/api/session');
    if (s.authenticated) return showApp();
    showGate(!s.password_set);
  } catch {
    showGate();
  }
}

function showGate(firstAccess = false) {
  $('#app').hidden = true;
  $('#gate').hidden = false;
  $('#password2-wrap').hidden = !firstAccess;
  $('#gate-title').textContent = firstAccess ? 'Set the panel password' : 'SentinelHost';
  $('#gate-sub').textContent = firstAccess
    ? 'First access: choose the password that protects this panel.'
    : 'Sign in to reach the panel.';
  $('#gate-btn').textContent = firstAccess ? 'Set the password' : 'Sign in';
  $('#gate-form').dataset.setup = firstAccess ? '1' : '';
  $('#password').value = '';
  $('#password2').value = '';
  $('#password').focus();
}

function showApp() {
  $('#gate').hidden = true;
  $('#app').hidden = false;
  loadEverything();
}

$('#gate-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const err = $('#gate-err');
  err.hidden = true;
  const password = $('#password').value;
  const setup = $('#gate-form').dataset.setup === '1';

  if (setup && password !== $('#password2').value) {
    err.textContent = 'The passwords do not match.';
    err.hidden = false;
    return;
  }
  try {
    await api(setup ? '/api/setup' : '/api/login', {
      method: 'POST', body: JSON.stringify({ password }),
    });
    showApp();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
});

$('#btn-logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* already signed out */ }
  location.reload();
});

// ------------------------------------------------------------------ navigation

$$('.nav-btn').forEach((b) => {
  b.addEventListener('click', () => {
    $$('.nav-btn').forEach((x) => x.classList.remove('active'));
    $$('.tab').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    $('#tab-' + b.dataset.tab).classList.add('active');
  });
});

// -------------------------------------------------------------------- overview

async function loadStatus() {
  const s = await api('/api/status');

  $('#kpi-confirmed').textContent = s.verdicts.confirmed;
  $('#kpi-likely').textContent = s.verdicts.likely;
  $('#kpi-suspicious').textContent = s.verdicts.suspicious;
  $('#kpi-quarantine').textContent = s.quarantine.active;

  const pill = $('#pill-findings');
  pill.textContent = s.pending_count;
  pill.hidden = s.pending_count === 0;

  $('#cycle-id').textContent = s.last_scan.scan_id || 'no cycle yet';
  const summary = $('#cycle-summary');
  clear(summary);
  [
    ['When', fmtDate(s.last_scan.finished_at)],
    ['Mode', s.last_scan.mode || '—'],
    ['Status', s.last_scan.status || '—'],
    ['Considered', s.last_scan.files_considered],
    ['Scanned', s.last_scan.files_scanned],
    ['Roots', (s.roots || []).join(', ')],
  ].forEach(([label, value]) => {
    const d = el('div');
    d.appendChild(el('small', { class: 'muted' }, label));
    d.appendChild(el('div', {}, String(value ?? '—')));
    summary.appendChild(d);
  });

  // Reduced coverage is a first-class warning, not a detail.
  const cov = $('#banner-coverage');
  if (s.engines.unavailable > 0) {
    cov.textContent =
      `${s.engines.unavailable} of ${s.engines.available + s.engines.unavailable} engines ` +
      `are unavailable. This site's coverage is reduced — see the Engines tab.`;
    cov.hidden = false;
  } else {
    cov.hidden = true;
  }

  const obs = $('#banner-observation');
  if (!s.automatic_action.allowed) {
    obs.textContent = `No automatic action will be taken: ${s.automatic_action.reason}.`;
    obs.hidden = false;
  } else {
    obs.hidden = true;
  }

  $('#side-foot').textContent =
    `${(s.roots || []).join(', ')}\nLast cycle: ${fmtDate(s.last_scan.finished_at)}`;
  $('#dash-sub').textContent =
    s.automatic_action.observation_mode
      ? 'Observation mode is on — the tool reports, but moves nothing.'
      : 'Automatic action is enabled for confirmed verdicts.';
}

async function loadEngineSummary() {
  const { engines } = await api('/api/engines');
  const box = $('#dash-engines');
  clear(box);
  engines.forEach((e) => {
    const line = el('div', { class: 'engine-line' });
    line.appendChild(el('span', {
      class: 'badge ' + (e.available ? 'b-good' : 'b-muted'),
    }, e.available ? 'ok' : 'down'));
    line.appendChild(el('span', { class: 'name' }, e.slug));
    line.appendChild(el('span', { class: 'muted small' }, `weight ${e.weight}`));
    line.appendChild(el('span', { class: 'reason' },
      e.available ? (e.version || '') : (e.unavailable_reason || 'unavailable')));
    box.appendChild(line);
  });
}

$('#btn-scan').addEventListener('click', async (ev) => {
  ev.target.disabled = true;
  ev.target.textContent = 'Scanning…';
  try {
    const r = await api('/api/scan', { method: 'POST', body: JSON.stringify({ full: false }) });
    toast(`Cycle ${r.scan_id} finished: ${r.files_scanned} file(s) scanned.`);
    await loadEverything();
  } catch (e) {
    toast(e.message, true);
  } finally {
    ev.target.disabled = false;
    ev.target.textContent = 'Scan now';
  }
});

// -------------------------------------------------------------------- findings

async function loadFindings() {
  const pending = $('#f-pending').checked ? '?pending=1' : '';
  const { verdicts } = await api('/api/verdicts' + pending);
  const list = $('#findings-list');
  clear(list);

  if (!verdicts || verdicts.length === 0) {
    list.appendChild(el('div', { class: 'card empty' },
      pending ? 'No finding is waiting for a decision.' : 'No finding recorded.'));
    return;
  }
  verdicts.forEach((v) => list.appendChild(verdictCard(v)));
}

function verdictCard(v) {
  const card = el('div', { class: 'card verdict ' + v.level });

  const head = el('div', { class: 'chart-head' });
  head.appendChild(el('span', { class: 'badge ' + LEVEL_CLASS[v.level] },
    LEVEL_LABEL[v.level] || v.level));
  head.appendChild(el('span', { class: 'muted small' }, `score ${v.score.toFixed(2)}`));
  head.appendChild(el('span', { class: 'spacer' }));
  head.appendChild(el('span', { class: 'muted small' }, fmtDate(v.created_at)));
  card.appendChild(head);

  card.appendChild(el('div', { class: 'path' }, v.file_path));

  const bar = el('div', { class: 'score-bar' });
  const fill = el('i');
  fill.style.width = Math.round(v.score * 100) + '%';
  bar.appendChild(fill);
  card.appendChild(bar);

  // The votes ARE the verdict. Without them the user would have to trust blindly.
  const t = el('table', { class: 'votes' });
  (v.votes || []).forEach((vote) => {
    const tr = el('tr');
    tr.appendChild(el('td', { class: 'eng' }, vote.engine));
    tr.appendChild(el('td', { class: 'calc' },
      `${vote.weight.toFixed(2)} × ${vote.confidence} = ${vote.effective_weight.toFixed(2)}`));
    tr.appendChild(el('td', {}, vote.rule));
    tr.appendChild(el('td', { class: 'muted' }, vote.category));
    t.appendChild(tr);
  });
  card.appendChild(t);

  if (v.abstentions && v.abstentions.length) {
    card.appendChild(el('p', { class: 'muted small' },
      `Abstentions: ${v.abstentions.join(', ')} — this cycle's coverage was reduced.`));
  }
  if (v.clean_reason) {
    card.appendChild(el('p', { class: 'small c-good' },
      `Veto applied: ${v.clean_reason}. This file will never be quarantined.`));
  }
  if (v.action_taken && v.action_taken !== 'none') {
    const txt = v.action_error ? `${v.action_taken} — ${v.action_error}` : v.action_taken;
    card.appendChild(el('p', { class: 'small muted' }, `Action: ${txt}`));
  }

  if (!v.acknowledged_by_user && v.level !== 'clean' && !v.clean_reason) {
    const actions = el('div', { class: 'actions' });
    actions.appendChild(decisionButton(v, 'quarantine', 'Quarantine', 'btn danger'));
    actions.appendChild(decisionButton(v, 'ignore', 'Ignore once', 'btn'));
    actions.appendChild(decisionButton(v, 'whitelist', 'Add to the whitelist', 'btn'));
    card.appendChild(actions);
  }
  return card;
}

function decisionButton(v, action, label, cls) {
  const b = el('button', { class: cls }, label);
  b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const r = await api(`/api/verdicts/${encodeURIComponent(v.verdict_id)}/decide`, {
        method: 'POST', body: JSON.stringify({ action }),
      });
      if (action === 'quarantine') {
        toast(`Quarantined (ref ${r.quarantine_ref}). The file is still restorable.`);
      } else {
        toast('Decision recorded.');
      }
      await loadEverything();
    } catch (e) {
      toast(e.message, true);
      b.disabled = false;
    }
  });
  return b;
}

$('#f-pending').addEventListener('change', loadFindings);

// ------------------------------------------------------------------ quarantine

async function loadQuarantine() {
  const all = $('#q-all').checked ? '?all=1' : '';
  const { items } = await api('/api/quarantine' + all);
  const tb = $('#tab-quar tbody');
  clear(tb);

  if (!items || items.length === 0) {
    const tr = el('tr');
    tr.appendChild(el('td', { colspan: '6', class: 'empty' }, 'The vault is empty.'));
    tb.appendChild(tr);
    return;
  }

  items.forEach((it) => {
    const tr = el('tr');
    tr.appendChild(el('td', { class: 'path' }, it.Ref));
    tr.appendChild(el('td', { class: 'path' }, it.OriginalPath));
    tr.appendChild(el('td', {}, fmtDate(it.QuarantinedAt)));
    tr.appendChild(el('td', {}, fmtDay(it.RetentionUntil)));

    const st = el('td');
    st.appendChild(el('span', {
      class: 'badge ' + (it.Status === 'quarantined' ? 'b-warn' : 'b-muted'),
    }, it.Status));
    tr.appendChild(st);

    const actions = el('td');
    if (it.Status === 'quarantined') {
      const restore = el('button', { class: 'btn sm' }, 'Restore');
      restore.addEventListener('click', async () => {
        restore.disabled = true;
        try {
          const r = await api(`/api/quarantine/${encodeURIComponent(it.Ref)}/restore`, { method: 'POST' });
          toast(`Restored byte for byte at ${r.restored_to}`);
          await loadEverything();
        } catch (e) {
          toast(e.message, true);
          restore.disabled = false;
        }
      });
      actions.appendChild(restore);

      const purge = el('button', { class: 'btn sm danger' }, 'Purge');
      purge.addEventListener('click', () => confirmPurge(it));
      actions.appendChild(purge);
    }
    tr.appendChild(actions);
    tb.appendChild(tr);
  });
}

$('#q-all').addEventListener('change', loadQuarantine);

function confirmPurge(item) {
  const modal = $('#modal');
  $('#modal-title').textContent = 'Purge permanently';
  $('#modal-body').textContent =
    `This deletes the copy of ${item.OriginalPath} from the vault. It is ` +
    `SentinelHost's only irreversible operation: after it the file can no longer be restored.`;
  $('#modal-input').value = '';
  modal.hidden = false;
  $('#modal-input').focus();

  $('#modal-ok').onclick = async () => {
    if ($('#modal-input').value !== 'purge') {
      toast('Type "purge" to confirm.', true);
      return;
    }
    try {
      await api(`/api/quarantine/${encodeURIComponent(item.Ref)}/purge`, {
        method: 'POST', body: JSON.stringify({ confirm: 'purge' }),
      });
      toast('The item was purged permanently.');
      modal.hidden = true;
      await loadEverything();
    } catch (e) {
      toast(e.message, true);
    }
  };
  $('#modal-cancel').onclick = () => { modal.hidden = true; };
}

// --------------------------------------------------------------------- engines

async function loadEngines() {
  const { engines } = await api('/api/engines');
  const list = $('#engines-list');
  clear(list);

  engines.forEach((e) => {
    const card = el('div', { class: 'card' });

    const head = el('div', { class: 'chart-head' });
    head.appendChild(el('h2', {}, e.name || e.slug));
    head.appendChild(el('span', {
      class: 'badge ' + (e.available ? 'b-good' : 'b-muted'),
    }, e.available ? 'available' : 'unavailable'));
    head.appendChild(el('span', { class: 'spacer' }));
    head.appendChild(el('span', { class: 'muted small' }, `weight ${e.weight}`));
    card.appendChild(head);

    if (!e.available && e.unavailable_reason) {
      // FR-001: the reason is mandatory. "Unavailable" on its own turns a solvable
      // problem into a mystery.
      card.appendChild(el('p', { class: 'small' }, e.unavailable_reason));
      const install = el('button', { class: 'btn sm' }, 'Install in my space');
      install.addEventListener('click', async () => {
        install.disabled = true;
        install.textContent = 'Installing…';
        try {
          await api(`/api/engines/${encodeURIComponent(e.slug)}/install`, { method: 'POST' });
          toast(`${e.slug} installed.`);
          await loadEverything();
        } catch (err) {
          toast(err.message, true);
          install.disabled = false;
          install.textContent = 'Install in my space';
        }
      });
      card.appendChild(install);
    } else if (e.version) {
      card.appendChild(el('p', { class: 'small muted' }, e.version));
    }

    const meta = el('div', { class: 'row3' });
    [
      ['License', e.license],
      ['Cost', e.cost],
      ['Signatures', fmtDate(e.signatures_updated_at)],
      ['Last run', fmtDate(e.last_run_at)],
      ['Last status', e.last_run_status || '—'],
    ].forEach(([k, v]) => {
      const d = el('div');
      d.appendChild(el('small', { class: 'muted' }, k));
      d.appendChild(el('div', { class: 'small' }, String(v || '—')));
      meta.appendChild(d);
    });
    card.appendChild(meta);
    list.appendChild(card);
  });
}

// --------------------------------------------------------------- configuration

let CFG = null;

async function loadConfig() {
  const r = await api('/api/config');
  CFG = r.config;
  $('#cfg-path').textContent = 'File: ' + r.path;

  // Schedule
  $('#s-incremental').value = CFG.schedule.incremental || '';
  $('#s-full').value = CFG.schedule.full_cron || '';
  $('#s-sig').value = CFG.schedule.signatures_cron || '';
  $('#s-mode').value = CFG.schedule.mode || 'cron';
  $('#s-nice').value = CFG.limits.nice;
  $('#s-maxsize').value = CFG.limits.max_file_size_mb;
  $('#s-timeout').value = CFG.limits.engine_timeout || '';
  $('#s-batch').value = CFG.limits.batch_size;
  $('#s-pause').value = CFG.limits.batch_pause || '';

  const cron = await api('/api/cron-line');
  $('#cron-box').textContent =
    `# incremental cycle (${cron.incremental})\n` +
    `0 * * * * sentinelhost scan --config ${cron.config_path} --quiet\n\n` +
    `# full scan\n` +
    `${cron.full_cron} sentinelhost scan --config ${cron.config_path} --full --quiet\n\n` +
    `# ${cron.hint}`;

  // Alerts
  const e = CFG.alerts.email;
  $('#e-enabled').checked = !!e.enabled;
  $('#e-host').value = e.host || '';
  $('#e-port').value = e.port || 587;
  $('#e-tls').value = e.tls || 'starttls';
  $('#e-user').value = e.username || '';
  $('#e-pass').value = e.password || '';
  $('#e-from').value = e.from || '';
  $('#e-to').value = (e.to || []).join(', ');
  $('#e-panel').value = e.panel_url || '';
  $('#e-digest').checked = !!e.digest_enabled;
  $('#e-digest-at').value = e.digest_at || '08:00';
  $$('.e-lvl').forEach((cb) => { cb.checked = (e.levels || []).includes(cb.value); });

  renderHooks(CFG.alerts.webhooks || []);

  // Settings
  $('#c-observation').checked = !!CFG.general.observation_mode;
  $('#c-grace').value = CFG.general.grace_period_days;
  $('#c-confirmed').value = CFG.verdict.confirmed_at;
  $('#c-likely').value = CFG.verdict.likely_at;
  $('#c-suspicious').value = CFG.verdict.suspicious_at;
  $('#c-retention').value = CFG.quarantine.retention_days;
  $('#c-autopurge').checked = !!CFG.quarantine.auto_purge;
  $('#c-whitelist').value = (CFG.verdict.whitelist || []).join('\n');
  $('#c-exclude').value = (CFG.limits.exclude || []).join('\n');
}

function renderHooks(hooks) {
  const box = $('#hooks-list');
  clear(box);
  hooks.forEach((h, i) => box.appendChild(hookCard(h, i)));
  if (hooks.length === 0) {
    box.appendChild(el('p', { class: 'muted small' }, 'No webhook registered.'));
  }
}

function hookCard(h, i) {
  const card = el('div', { class: 'hook', dataset: { idx: String(i) } });

  const line = el('div', { class: 'row2' });
  line.appendChild(field('ID', 'h-id', h.id));
  line.appendChild(field('URL', 'h-url', h.url));
  line.appendChild(field('Secret (HMAC)', 'h-secret', h.secret, 'password'));
  card.appendChild(line);

  const evs = el('fieldset', { class: 'levels' });
  evs.appendChild(el('legend', {}, 'Signed events'));
  ['verdict.confirmed', 'verdict.likely', 'verdict.suspicious',
    'quarantine.action', 'scan.completed', 'engine.failed'].forEach((ev) => {
    const lbl = el('label', { class: 'inline' });
    const cb = el('input', { type: 'checkbox', class: 'h-ev', value: ev });
    cb.checked = (h.events || []).includes(ev);
    lbl.appendChild(cb);
    lbl.appendChild(document.createTextNode(' ' + ev));
    evs.appendChild(lbl);
  });
  card.appendChild(evs);

  const actions = el('div', { class: 'actions' });
  const enabledLabel = el('label', { class: 'inline' });
  const enabledBox = el('input', { type: 'checkbox', class: 'h-enabled' });
  enabledBox.checked = !!h.enabled;
  enabledLabel.appendChild(enabledBox);
  enabledLabel.appendChild(document.createTextNode(' enabled'));
  actions.appendChild(enabledLabel);

  const test = el('button', { class: 'btn sm' }, 'Send a test');
  test.addEventListener('click', () => testWebhook(h.id, card));
  actions.appendChild(test);

  const remove = el('button', { class: 'btn sm danger' }, 'Remove');
  remove.addEventListener('click', () => card.remove());
  actions.appendChild(remove);
  card.appendChild(actions);

  card.appendChild(el('div', { class: 'result', hidden: 'hidden' }));
  return card;
}

function field(label, cls, value, type = 'text') {
  const l = el('label', {}, label);
  const i = el('input', { class: cls, type });
  i.value = value || '';
  l.appendChild(i);
  return l;
}

$('#btn-add-hook').addEventListener('click', () => {
  $('#hooks-list').appendChild(hookCard(
    { id: '', url: '', secret: '', events: ['verdict.confirmed'], enabled: true },
    $$('.hook').length));
});

// ----------------------------------------------------------------------- saves

async function save(patch, okMsg) {
  try {
    const r = await api('/api/config', { method: 'PUT', body: JSON.stringify(patch) });
    toast(okMsg);
    if (r.warnings && r.warnings.length) {
      r.warnings.forEach((a) => toast('Warning — ' + a, true));
    }
    await loadConfig();
  } catch (e) {
    toast(e.message, true);
  }
}

$('#btn-save-schedule').addEventListener('click', () => save({
  incremental: $('#s-incremental').value,
  full_cron: $('#s-full').value,
  signatures_cron: $('#s-sig').value,
  schedule_mode: $('#s-mode').value,
  nice: Number($('#s-nice').value),
  max_file_size_mb: Number($('#s-maxsize').value),
  engine_timeout: $('#s-timeout').value,
  batch_size: Number($('#s-batch').value),
  batch_pause: $('#s-pause').value,
}, 'The schedule was saved. It applies from the next cycle on.'));

$('#btn-save-email').addEventListener('click', () => save({
  email: {
    enabled: $('#e-enabled').checked,
    host: $('#e-host').value,
    port: Number($('#e-port').value),
    tls: $('#e-tls').value,
    username: $('#e-user').value,
    password: $('#e-pass').value,
    from: $('#e-from').value,
    to: $('#e-to').value.split(',').map((s) => s.trim()).filter(Boolean),
    levels: $$('.e-lvl').filter((cb) => cb.checked).map((cb) => cb.value),
    digest_enabled: $('#e-digest').checked,
    digest_at: $('#e-digest-at').value,
    panel_url: $('#e-panel').value,
  },
}, 'The e-mail configuration was saved.'));

$('#btn-save-hooks').addEventListener('click', () => {
  const hooks = $$('.hook').map((card) => ({
    id: $('.h-id', card).value.trim(),
    url: $('.h-url', card).value.trim(),
    secret: $('.h-secret', card).value,
    enabled: $('.h-enabled', card).checked,
    events: $$('.h-ev', card).filter((cb) => cb.checked).map((cb) => cb.value),
  }));
  save({ webhooks: hooks }, 'The webhooks were saved.');
});

$('#btn-save-config').addEventListener('click', () => save({
  observation_mode: $('#c-observation').checked,
  grace_period_days: Number($('#c-grace').value),
  confirmed_at: Number($('#c-confirmed').value),
  likely_at: Number($('#c-likely').value),
  suspicious_at: Number($('#c-suspicious').value),
  retention_days: Number($('#c-retention').value),
  auto_purge: $('#c-autopurge').checked,
  whitelist: $('#c-whitelist').value.split('\n').map((s) => s.trim()).filter(Boolean),
  exclude: $('#c-exclude').value.split('\n').map((s) => s.trim()).filter(Boolean),
}, 'The settings were saved.'));

// ----------------------------------------------------------------------- tests

$('#btn-test-email').addEventListener('click', async (ev) => {
  const box = $('#res-email');
  ev.target.disabled = true;
  box.hidden = false;
  box.className = 'result';
  box.textContent = 'Sending…';
  try {
    const r = await api('/api/alert/test', {
      method: 'POST', body: JSON.stringify({ channel: 'email' }),
    });
    // The REAL error goes to the screen: finding out that the hosting blocks port
    // 587 is this button's entire purpose.
    box.className = 'result ' + (r.ok ? 'ok' : 'bad');
    box.textContent = r.message + (r.error ? '\n' + r.error : '');
  } catch (e) {
    box.className = 'result bad';
    box.textContent = e.message;
  } finally {
    ev.target.disabled = false;
  }
});

async function testWebhook(id, card) {
  const box = $('.result', card);
  box.hidden = false;
  box.className = 'result';
  box.textContent = 'Sending…';
  try {
    const r = await api('/api/alert/test', {
      method: 'POST', body: JSON.stringify({ channel: 'webhook', id }),
    });
    box.className = 'result ' + (r.ok ? 'ok' : 'bad');
    let txt = r.message;
    if (r.response_body) txt += '\n\nresponse: ' + r.response_body;
    box.textContent = txt;
  } catch (e) {
    box.className = 'result bad';
    box.textContent = e.message;
  }
}

// ------------------------------------------------------------------ full reload

async function loadEverything() {
  const tasks = [
    ['the overview', loadStatus],
    ['the engines', loadEngineSummary],
    ['the findings', loadFindings],
    ['the quarantine', loadQuarantine],
    ['the engines', loadEngines],
    ['the configuration', loadConfig],
  ];
  // One area that fails must not wipe out the whole panel: the user still needs to
  // see the others.
  for (const [name, fn] of tasks) {
    try {
      await fn();
    } catch (e) {
      if (e.message !== 'session expired') {
        toast(`Could not load ${name}: ${e.message}`, true);
      }
    }
  }
}

bootstrap();
