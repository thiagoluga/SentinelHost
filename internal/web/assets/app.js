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

// Where the panel is mounted, worked out from the page's own URL.
//
// The panel used to address itself with absolute paths — /api/status, /app.css — which
// works only when it is served at the root of a domain. Behind any reverse proxy on a
// sub-path, and that includes the PHP bridge for shared hosting, the browser asks the
// SITE for /api/status instead of the panel, and every request 404s while the page
// itself loads. Unstyled, inert, and with nothing on screen saying why.
//
// document.baseURI already carries the directory the page came from, so relative URLs
// resolve correctly wherever the panel is mounted, including the root.
const BASE = new URL('.', document.baseURI);

/**
 * Turn a panel-relative path into an absolute one for wherever we are mounted.
 *
 * The origin is checked rather than assumed. document.baseURI is not a constant: a
 * `<base href>` element changes it, and one injected into this page would silently
 * redirect every API call — including the ones that quarantine and restore files — to
 * somewhere else. Nothing renders untrusted HTML here today, and the check costs one
 * comparison, which is the right trade for a guarantee that would otherwise depend on
 * that staying true forever.
 */
function url(path) {
  const resolved = new URL(String(path).replace(/^\//, ''), BASE);
  if (resolved.origin !== window.location.origin) {
    throw new Error('refusing to send a panel request off-origin');
  }
  return resolved.pathname + resolved.search;
}

async function api(path, opts = {}) {
  const resp = await fetch(url(path), {
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
  // Only on first access: after a password exists, the token is refused anyway, and a
  // field that does nothing invites somebody to go looking for a value to put in it.
  $('#setup-token-wrap').hidden = !firstAccess;
  $('#gate-title').textContent = firstAccess ? 'Set the panel password' : 'SentinelHost';
  $('#gate-sub').textContent = firstAccess
    ? 'First access: choose the password that protects this panel.'
    : 'Sign in to reach the panel.';
  $('#gate-btn').textContent = firstAccess ? 'Set the password' : 'Sign in';
  $('#gate-form').dataset.setup = firstAccess ? '1' : '';
  $('#password').value = '';
  $('#password2').value = '';
  $('#setup-token').value = '';
  $('#password').focus();
}

function showApp() {
  $('#gate').hidden = true;
  $('#app').hidden = false;

  // The URL decides, then whatever the markup marked active, then the overview. The last
  // fallback matters: a hash naming a tab that no longer exists must not leave the panel
  // with nothing selected.
  const marked = $('.tab.active');
  showTab(tabFromHash() || (marked ? marked.id.replace(/^tab-/, '') : 'dash') || 'dash');
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
    // The token travels only with setup. Sending it to /api/login would put a credential
    // in a request that has no use for it.
    const payload = setup
      ? { password, setup_token: $('#setup-token').value.trim() }
      : { password };
    await api(setup ? '/api/setup' : '/api/login', {
      method: 'POST', body: JSON.stringify(payload),
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

/**
 * Which tab is open lives in the URL.
 *
 * Reloading a panel and landing back on the overview is a small thing that happens
 * constantly: this one runs behind a bridge that restarts the backend, so a reload is
 * routine rather than rare. It also makes a tab linkable — "look at the findings" can be
 * a URL rather than an instruction.
 *
 * The hash, not a query string. It never reaches the server, so it costs nothing on an
 * account with a ceiling on requests, and it survives the bridge without the bridge
 * having to forward anything. Back and forward work for free, because changing the hash
 * is a history entry and `hashchange` is what reacts to it.
 */
function tabFromHash() {
  // Anything not in TAB_LOADERS is not a tab, whatever the URL says.
  //
  // This value comes from the address bar, so it is attacker-chosen: a link someone else
  // wrote opens this panel. It is validated against the known set BEFORE it is used to
  // build a selector — `#tab-` plus arbitrary text is a selector injection at best and a
  // thrown exception that blanks the panel at worst.
  const name = decodeURIComponent((location.hash || '').replace(/^#/, ''));
  return Object.prototype.hasOwnProperty.call(TAB_LOADERS, name) ? name : '';
}

/** Show a tab. The name must already have been validated. */
function showTab(tab) {
  const pane = $('#tab-' + tab);
  if (!pane) return;

  $$('.nav-btn').forEach((x) => x.classList.toggle('active', x.dataset.tab === tab));
  $$('.tab').forEach((x) => x.classList.remove('active'));
  pane.classList.add('active');

  // Fetched when it is first opened, not before. See TAB_LOADERS.
  loadTab(tab);
}

$$('.nav-btn').forEach((b) => {
  b.addEventListener('click', () => {
    // Set the hash and let the one listener below do the work, rather than switching here
    // and updating the URL as well. Two paths that both change tabs drift apart — one of
    // them ends up missing a step, and it is always the one nobody clicks.
    if (tabFromHash() === b.dataset.tab) {
      showTab(b.dataset.tab); // same tab: no hashchange will fire, so act directly
      return;
    }
    location.hash = b.dataset.tab;
  });
});

window.addEventListener('hashchange', () => {
  const tab = tabFromHash();
  // An unknown hash leaves the panel where it is instead of blanking it. Someone editing
  // the URL by hand should not be able to produce an empty page.
  if (tab) showTab(tab);
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

  // Reduced coverage is a first-class warning, not a detail. And "reduced" and "none"
  // are not the same warning.
  //
  // With every engine unavailable this banner used to print the same sentence it prints
  // when one of four is missing, above four KPIs reading zero. Nothing on the screen
  // told the reader that those zeros mean nothing at all — which is the failure this
  // whole project is organised against, arriving on the one surface built for people who
  // are not going to read a log. The CLI grew the same fix (DECISIONS.md D-031); this is
  // its counterpart.
  const total = s.engines.available + s.engines.unavailable;
  const cov = $('#banner-coverage');
  const nothingScanned = s.engines.available === 0 && total > 0;
  clear(cov);
  if (nothingScanned) {
    cov.className = 'banner bad';
    cov.appendChild(el('b', {}, 'Nothing was scanned.'));
    cov.appendChild(el('span', {}, ` All ${total} engines are unavailable, so the counts ` +
      `below say nothing about this site. Open the Engines tab: each one explains what it ` +
      `needs, and most are one command or one request to your host.`));
    cov.hidden = false;
  } else if (s.engines.unavailable > 0) {
    cov.className = 'banner';
    cov.textContent =
      `${s.engines.unavailable} of ${total} engines ` +
      `are unavailable. This site's coverage is reduced — see the Engines tab.`;
    cov.hidden = false;
  } else {
    cov.hidden = true;
  }

  // And the numbers themselves stop pretending. A zero that was never measured must not
  // look like a zero that was: it is dimmed, and it says so on hover for anyone checking.
  ['#kpi-confirmed', '#kpi-likely', '#kpi-suspicious'].forEach((sel) => {
    const node = $(sel);
    node.classList.toggle('unmeasured', nothingScanned);
    node.title = nothingScanned
      ? 'Not measured: no engine was able to run in the last cycle.'
      : '';
  });

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
    await refreshAfterAction();
  } catch (e) {
    toast(e.message, true);
  } finally {
    ev.target.disabled = false;
    ev.target.textContent = 'Scan now';
  }
});

// -------------------------------------------------------------------- findings

// Where each location sits in the reading order, and what to say about it.
//
// Reachable first, because that is the only group where somebody can execute the file
// right now. The trash last: on a real account it produced 209 findings — framework code
// from Laravel and Symfony in deleted installations — against a handful on the live site,
// and an undifferentiated list buries the ones that matter under the ones that do not.
const LOCATIONS = [
  { key: 'web_reachable',   title: 'Served by the web',        note: 'A visitor can request these files.', open: true },
  { key: 'unknown',         title: 'Location unknown',         note: 'No document root is configured, so whether the web serves these is not known. Treated as if it does.', open: true },
  { key: '',                title: 'Location not recorded',    note: 'Found before this cycle started classifying paths.', open: true },
  { key: 'outside_docroot', title: 'Outside every document root', note: 'Nothing serves these. They are still on the account, and a copy or a restore brings them back into play.', open: false },
  { key: 'trash',           title: 'In the trash',             note: 'Nothing serves these — but the trash restores with one click, and restoring the site restores them with it.', open: false },
];

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

  const groups = new Map(LOCATIONS.map((l) => [l.key, []]));
  verdicts.forEach((v) => {
    const key = groups.has(v.file_location || '') ? (v.file_location || '') : '';
    groups.get(key).push(v);
  });

  LOCATIONS.forEach((loc) => {
    const found = groups.get(loc.key);
    if (!found.length) return;
    list.appendChild(locationGroup(loc, found));
  });
}

// One collapsible section per location.
//
// <details> rather than a div and a click handler: it collapses without JavaScript, it is
// reachable from the keyboard, and a screen reader announces its state — none of which a
// hand-rolled toggle gets for free.
//
// The groups that are not urgent start CLOSED, and that is the only thing hidden: the
// count and the reason sit in the summary, always visible. Anything out of sight stays
// counted and explained, which is the same rule the scan report follows for skipped files.
function locationGroup(loc, verdicts) {
  const box = el('details', { class: 'loc-group' });
  if (loc.open) box.open = true;

  const worst = ['confirmed', 'likely', 'suspicious', 'clean']
    .find((lvl) => verdicts.some((v) => v.level === lvl));

  const sum = el('summary');
  sum.appendChild(el('b', {}, loc.title));
  sum.appendChild(el('span', { class: 'count' }, `${verdicts.length}`));
  if (worst) {
    sum.appendChild(el('span', { class: `chip lvl-${worst}` }, `worst: ${worst}`));
  }
  sum.appendChild(el('small', { class: 'muted' }, loc.note));
  box.appendChild(sum);

  verdicts.forEach((v) => box.appendChild(verdictCard(v)));
  return box;
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

  card.appendChild(evidenceBlock(v));

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

/**
 * What the engine actually saw, fetched when somebody asks for it.
 *
 * The votes above say a file was flagged and by whom. They do not say WHY, and "why" is
 * the difference between a user who can decide and one who has to trust us. The engines
 * already record it — AMWScan keeps the offending line and its number, yara keeps the
 * strings that matched and their byte offset — and it has been going into the database
 * and no further.
 *
 * Loaded on demand rather than with the list. A findings page holding two hundred cards
 * would otherwise be two hundred extra requests, on an account that has a ceiling on how
 * many may run at once.
 *
 * Everything here is snippet text chosen by whoever wrote the malware, and it enters the
 * DOM through textContent — never innerHTML — because a file named
 * `<img src=x onerror=…>.php` would otherwise turn this panel into an attack on the
 * person reading it. It is already sanitized and length-capped server side; this is the
 * second barrier, and the CSP is the third.
 */
function evidenceBlock(v) {
  const box = el('details', { class: 'evidence' });
  const sum = el('summary');
  sum.appendChild(el('span', {}, 'What the engines saw'));
  box.appendChild(sum);

  const body = el('div', { class: 'evidence-body' });
  body.appendChild(el('p', { class: 'muted small' }, 'Loading…'));
  box.appendChild(body);

  let loaded = false;
  box.addEventListener('toggle', async () => {
    if (!box.open || loaded) return;
    loaded = true;
    try {
      const { findings } = await api(`/api/verdicts/${encodeURIComponent(v.verdict_id)}`);
      renderEvidence(body, findings || []);
    } catch (e) {
      loaded = false; // so opening it again retries instead of staying on the error
      clear(body);
      body.appendChild(el('p', { class: 'small c-warn' },
        `Could not load the evidence: ${e.message}`));
    }
  });
  return box;
}

function renderEvidence(body, findings) {
  clear(body);
  if (!findings.length) {
    // "This cycle", not "this file". The evidence is scoped to the cycle that produced
    // the verdict you are looking at, so an earlier cycle may well have recorded some —
    // and a message saying otherwise would send someone looking for a bug that is not
    // there.
    body.appendChild(el('p', { class: 'muted small' },
      'The cycle that produced this verdict recorded no detail.'));
    return;
  }

  findings.forEach((f) => {
    const item = el('div', { class: 'evidence-item' });

    const head = el('div', { class: 'evidence-head' });
    head.appendChild(el('b', {}, f.engine));
    head.appendChild(el('span', { class: 'muted' }, f.rule));
    // Where in the file. AMWScan counts lines; yara counts bytes. Saying which is which
    // matters — "offset 4211" and "line 4211" send someone to very different places.
    if (f.matched_offset) {
      head.appendChild(el('span', { class: 'where' },
        f.engine === 'php-malware-finder' ? `byte ${f.matched_offset}` : `line ${f.matched_offset}`));
    }
    item.appendChild(head);

    if (f.matched_content) {
      // A <pre> so whitespace survives: indentation and line breaks are often the
      // clearest sign that something was pasted into an otherwise tidy file.
      item.appendChild(el('pre', { class: 'snippet' }, f.matched_content));
    } else {
      // maldet reports only which signature matched, never a snippet. Saying so beats
      // an empty box that looks like something failed to load.
      item.appendChild(el('p', { class: 'muted small' },
        `${f.engine} reports which signature matched, not the text that matched it.`));
    }
    body.appendChild(item);
  });
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
      await refreshAfterAction();
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
          await refreshAfterAction();
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
      await refreshAfterAction();
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
          await refreshAfterAction();
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
  line.appendChild(formatField(h.format || 'raw'));
  card.appendChild(line);

  // Slack and Discord reject an arbitrary payload, so the format is not cosmetic:
  // it is what makes the delivery arrive at all. Neither verifies a signature,
  // which is why the secret only means something for `raw`.
  card.appendChild(el('p', { class: 'muted small' },
    h.format === 'slack' || h.format === 'discord'
      ? 'Slack and Discord do not verify signatures: the delivery is still signed, but only the raw format has a receiver that reads it.'
      : 'The raw format sends this project’s envelope, signed with HMAC-SHA256.'));

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

/** The body shape for the destination. Slack and Discord reject our envelope. */
function formatField(value) {
  const l = el('label', {}, 'Body format');
  const s = el('select', { class: 'h-format' });
  [
    ['raw', 'raw (this project’s signed envelope)'],
    ['slack', 'Slack incoming webhook'],
    ['discord', 'Discord webhook'],
  ].forEach(([v, text]) => {
    const o = el('option', { value: v }, text);
    if (v === value) o.selected = true;
    s.appendChild(o);
  });
  l.appendChild(s);
  return l;
}

$('#btn-add-hook').addEventListener('click', () => {
  $('#hooks-list').appendChild(hookCard(
    { id: '', url: '', secret: '', events: ['verdict.confirmed'], enabled: true, format: 'raw' },
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
    format: $('.h-format', card).value,
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

// ------------------------------------------------------------------ tab loading

// What each tab needs, and nothing else.
//
// The panel used to fetch all of this at startup: six loaders, eight API calls, for one
// visible tab. On a shared hosting account every one of those is a PHP process holding a
// worker while it proxies to the panel, and the account has a hard ceiling on how many
// may run at once. Loading five invisible tabs to show one is the kind of waste
// Principle IV exists to prevent — the tool is a guest on somebody's hosting.
//
// `the engines` appeared twice, once for the dashboard summary and once for its own tab,
// so /api/engines was requested twice on every single page view.
const TAB_LOADERS = {
  dash:       [['the overview', loadStatus], ['the engines', loadEngineSummary],
               ['the update check', loadUpdate]],
  findings:   [['the findings', loadFindings]],
  quarantine: [['the quarantine', loadQuarantine]],
  engines:    [['the engines', loadEngines]],
  schedule:   [['the configuration', loadConfig]],
  alerts:     [['the configuration', loadConfig]],
  settings:   [['the configuration', loadConfig]],
};

// Tabs already fetched. Cleared on an explicit refresh, so "reload" still means reload.
const loaded = new Set();

async function loadTab(tab, { force = false } = {}) {
  const tasks = TAB_LOADERS[tab];
  if (!tasks || (loaded.has(tab) && !force)) return;
  loaded.add(tab);

  // Sequential, not concurrent. Four requests at once from one page view is what a
  // shared account notices, and nothing here is worth racing for.
  for (const [name, fn] of tasks) {
    try {
      await fn();
    } catch (e) {
      // One area failing must not wipe out the panel: the user still needs the others.
      // And the tab is un-marked so opening it again retries rather than showing a
      // blank pane forever.
      loaded.delete(tab);
      if (e.message !== 'session expired') {
        toast(`Could not load ${name}: ${e.message}`, true);
      }
    }
  }
}

/** Re-fetch what is on screen right now. */
async function reloadCurrentTab() {
  const active = $('.tab.active');
  if (active) await loadTab(active.id.replace(/^tab-/, ''), { force: true });
}

/**
 * After something that changed state — a scan, a decision, a restore, a purge.
 *
 * Everything is marked stale, but only the visible tab is fetched. Quarantining a file
 * changes the findings AND the quarantine AND the dashboard counts, so none of them can
 * be trusted afterwards; fetching all of them to show one is the waste this change exists
 * to remove. The rest re-fetch when they are opened.
 */
async function refreshAfterAction() {
  loaded.clear();
  await reloadCurrentTab();
}

bootstrap();

// ------------------------------------------------------------------ updates

/**
 * Tell the user a newer version exists. Never install one on our own.
 *
 * The whole design of the updater rests on this: a security tool that replaces itself
 * unattended on shared hosting behaves exactly the way the things it hunts behave, and
 * from the outside the user cannot tell the difference. So the panel reports, and a person
 * decides.
 *
 * It is also quiet on failure — but not silent. If the release listing cannot be reached,
 * the banner stays hidden rather than claiming the tool is current: "I could not check" and
 * "you are up to date" are different sentences, and only one of them is safe to guess.
 */
async function loadUpdate() {
  const banner = $('#update-banner');
  if (!banner) return;

  let s;
  try {
    s = await api('/api/update');
  } catch {
    // A failed check is not news. It is reported where somebody looking for it will find
    // it, rather than as a banner nobody can act on.
    return;
  }
  if (!s) return;

  // The running version, always — whether or not there is anything to update to. Somebody
  // reporting a problem needs to be able to say which version they are on without a shell,
  // and until now the panel never said.
  const side = $('#side-version');
  if (side && s.current) side.textContent = s.current;

  // Already installed, waiting for a restart. This is a DIFFERENT state from "an update
  // exists", and showing the second one here is how a user who installed and reloaded
  // concludes the update failed — the banner would ask them to install what they just did.
  if (s.pending_restart) {
    $('#update-title').textContent = `${s.on_disk} is installed and waiting`;
    $('#update-detail').textContent =
      `The panel is still running ${s.current}. Restarting is safe: anything in progress ` +
      `finishes first, and ${s.current} is kept so you can go back.`;
    $('#update-notes-box').hidden = true;
    $('#update-install').hidden = true;
    $('#update-restart').hidden = false;
    $('#update-dismiss').textContent = 'Later';
    banner.hidden = false;
    return;
  }

  if (!s.newer) return;

  // textContent throughout: every string below comes from a release listing, which is not
  // ours. The notes especially — markdown written by whoever cut the release, displayed
  // and never interpreted.
  $('#update-title').textContent = `SentinelHost ${s.latest} is available`;
  $('#update-detail').textContent =
    `You are running ${s.current}. The new binary is verified against the signing key ` +
    `built into this one, and the current binary is kept so you can go back.`;

  const box = $('#update-notes-box');
  if (s.notes && s.notes.trim()) {
    $('#update-notes').textContent = s.notes.trim();
    box.hidden = false;
  } else {
    box.hidden = true;
  }
  const link = $('#update-notes-link');
  if (s.notes_url) {
    link.href = s.notes_url;
    link.hidden = false;
  } else {
    link.hidden = true;
  }

  banner.hidden = false;
}

$('#update-dismiss')?.addEventListener('click', () => {
  // Hidden for this page view only, deliberately not remembered. An update the user
  // postponed once should still be visible tomorrow — a dismissal that persists is how a
  // security update gets forgotten permanently.
  $('#update-banner').hidden = true;
});

$('#update-install')?.addEventListener('click', async () => {
  const btn = $('#update-install');
  btn.disabled = true;
  btn.textContent = 'Installing…';
  try {
    const r = await api('/api/update', { method: 'POST' });

    // An update replaces the FILE. This process is still the old program, with the old
    // code in memory — so the banner turns into the one action that finishes the job,
    // rather than a sentence explaining a problem the user cannot act on without a shell.
    $('#update-title').textContent = `${r.installed} is installed`;
    $('#update-detail').textContent =
      'The panel is still running the previous version until it restarts. Restarting is ' +
      'safe: anything in progress finishes first, and the previous binary is kept.';
    $('#update-notes-box').hidden = true;
    btn.hidden = true;
    $('#update-dismiss').textContent = 'Later';
    $('#update-restart').hidden = false;
  } catch (e) {
    // Which failure it was matters more here than anywhere else in the panel: a refused
    // signature is not a network problem.
    toast(`The update was not installed: ${e.message}`, true);
    btn.disabled = false;
    btn.textContent = 'Install it';
  }
});

$('#update-restart')?.addEventListener('click', async () => {
  const btn = $('#update-restart');
  btn.disabled = true;
  btn.textContent = 'Restarting…';
  try {
    await api('/api/restart', { method: 'POST' });
  } catch {
    // Expected, and not a failure: the panel stops while answering, so the connection
    // often drops before the response arrives. Whether it stopped is decided below by
    // asking, not by whether this request completed.
  }

  // Wait for it to come back rather than claiming it has. Behind the bridge the next
  // request starts the new binary; started by hand, nothing restarts it, and saying so is
  // better than a spinner that never resolves.
  for (let i = 0; i < 12; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const s = await api('/api/update');
      if (s && s.current) {
        $('#side-version').textContent = s.current;
        $('#update-banner').hidden = true;
        toast(`Restarted. Now running ${s.current}.`);
        return;
      }
    } catch { /* still down; keep waiting */ }
  }
  toast('The panel stopped but has not come back. If you started it yourself rather than ' +
        'through the bridge, start it again.', true);
});
