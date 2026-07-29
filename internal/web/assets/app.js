/* Painel do SentinelHost — JS vanilla, sem framework e sem build step.
 *
 * Regra que atravessa este arquivo: TODO texto vindo do servidor entra no DOM
 * por textContent, nunca por innerHTML. Os caminhos de arquivo exibidos aqui
 * foram escolhidos pelo ATACANTE — um arquivo chamado
 * `<img src=x onerror=...>.php` transformaria o painel em vetor de ataque
 * contra o dono do site. A CSP e a segunda barreira; esta e a primeira.
 */
'use strict';

// ---------------------------------------------------------------- utilitarios

const $ = (sel, raiz = document) => raiz.querySelector(sel);
const $$ = (sel, raiz = document) => Array.from(raiz.querySelectorAll(sel));

/** Cria um elemento. `texto` sempre vira textContent. */
function el(tag, attrs = {}, texto) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'dataset') Object.assign(n.dataset, v);
    else n.setAttribute(k, v);
  }
  if (texto !== undefined) n.textContent = texto;
  return n;
}

function limpar(n) { while (n.firstChild) n.removeChild(n.firstChild); }

let toastTimer;
function toast(msg, ruim = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('bad', ruim);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 5200);
}

async function api(caminho, opts = {}) {
  const resp = await fetch(caminho, {
    credentials: 'same-origin',
    headers: opts.body ? { 'Content-Type': 'application/json' } : {},
    ...opts,
  });
  let dados = null;
  try { dados = await resp.json(); } catch { /* resposta sem corpo */ }

  if (resp.status === 401) {
    mostrarGate();
    throw new Error('sessao expirada');
  }
  if (!resp.ok) {
    throw new Error((dados && dados.error) || `HTTP ${resp.status}`);
  }
  return dados;
}

function fmtData(s) {
  if (!s || s.startsWith('0001-01-01')) return '—';
  const d = new Date(s);
  if (isNaN(d)) return '—';
  return d.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'short' });
}

function fmtDia(s) {
  if (!s || s.startsWith('0001-01-01')) return 'nunca expira';
  const d = new Date(s);
  return isNaN(d) ? '—' : d.toLocaleDateString('pt-BR');
}

const CLASSE_NIVEL = {
  confirmed: 'b-crit', likely: 'b-serious', suspicious: 'b-warn', clean: 'b-good',
};
const ROTULO_NIVEL = {
  confirmed: 'confirmado', likely: 'provável', suspicious: 'suspeito', clean: 'limpo',
};

// ---------------------------------------------------------------- autenticacao

async function bootstrap() {
  try {
    const s = await api('/api/session');
    if (s.authenticated) return mostrarApp();
    mostrarGate(!s.password_set);
  } catch {
    mostrarGate();
  }
}

function mostrarGate(primeiroAcesso = false) {
  $('#app').hidden = true;
  $('#gate').hidden = false;
  $('#senha2-wrap').hidden = !primeiroAcesso;
  $('#gate-title').textContent = primeiroAcesso ? 'Defina a senha do painel' : 'SentinelHost';
  $('#gate-sub').textContent = primeiroAcesso
    ? 'Primeiro acesso: escolha a senha que protege este painel.'
    : 'Entre para acessar o painel.';
  $('#gate-btn').textContent = primeiroAcesso ? 'Definir senha' : 'Entrar';
  $('#gate-form').dataset.setup = primeiroAcesso ? '1' : '';
  $('#senha').value = '';
  $('#senha2').value = '';
  $('#senha').focus();
}

function mostrarApp() {
  $('#gate').hidden = true;
  $('#app').hidden = false;
  carregarTudo();
}

$('#gate-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const erro = $('#gate-err');
  erro.hidden = true;
  const senha = $('#senha').value;
  const setup = $('#gate-form').dataset.setup === '1';

  if (setup && senha !== $('#senha2').value) {
    erro.textContent = 'As senhas não conferem.';
    erro.hidden = false;
    return;
  }
  try {
    await api(setup ? '/api/setup' : '/api/login', {
      method: 'POST', body: JSON.stringify({ password: senha }),
    });
    mostrarApp();
  } catch (e) {
    erro.textContent = e.message;
    erro.hidden = false;
  }
});

$('#btn-logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch { /* ja deslogado */ }
  location.reload();
});

// ---------------------------------------------------------------- navegacao

$$('.nav-btn').forEach((b) => {
  b.addEventListener('click', () => {
    $$('.nav-btn').forEach((x) => x.classList.remove('active'));
    $$('.tab').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    $('#tab-' + b.dataset.tab).classList.add('active');
  });
});

// ---------------------------------------------------------------- visao geral

async function carregarStatus() {
  const s = await api('/api/status');

  $('#kpi-confirmed').textContent = s.verdicts.confirmed;
  $('#kpi-likely').textContent = s.verdicts.likely;
  $('#kpi-suspicious').textContent = s.verdicts.suspicious;
  $('#kpi-quarantine').textContent = s.quarantine.active;

  const pill = $('#pill-findings');
  pill.textContent = s.pending_count;
  pill.hidden = s.pending_count === 0;

  $('#ciclo-id').textContent = s.last_scan.scan_id || 'nenhum ciclo ainda';
  const resumo = $('#ciclo-resumo');
  limpar(resumo);
  [
    ['Quando', fmtData(s.last_scan.finished_at)],
    ['Modo', s.last_scan.mode || '—'],
    ['Status', s.last_scan.status || '—'],
    ['Considerados', s.last_scan.files_considered],
    ['Escaneados', s.last_scan.files_scanned],
    ['Raízes', (s.roots || []).join(', ')],
  ].forEach(([rotulo, valor]) => {
    const d = el('div');
    d.appendChild(el('small', { class: 'muted' }, rotulo));
    d.appendChild(el('div', {}, String(valor ?? '—')));
    resumo.appendChild(d);
  });

  // Cobertura reduzida e um aviso de primeira classe, nao um detalhe.
  const cob = $('#banner-cobertura');
  if (s.engines.unavailable > 0) {
    cob.textContent =
      `${s.engines.unavailable} de ${s.engines.available + s.engines.unavailable} engines ` +
      `estão indisponíveis. A cobertura deste site está reduzida — veja a aba Engines.`;
    cob.hidden = false;
  } else {
    cob.hidden = true;
  }

  const obs = $('#banner-observacao');
  if (!s.automatic_action.allowed) {
    obs.textContent = `Nenhuma ação automática será executada: ${s.automatic_action.reason}.`;
    obs.hidden = false;
  } else {
    obs.hidden = true;
  }

  $('#side-foot').textContent =
    `${(s.roots || []).join(', ')}\nÚltimo ciclo: ${fmtData(s.last_scan.finished_at)}`;
  $('#dash-sub').textContent =
    s.automatic_action.observation_mode
      ? 'Modo observação ligado — a ferramenta relata, mas não move nada.'
      : 'Ação automática habilitada para vereditos confirmados.';
}

async function carregarEnginesResumo() {
  const { engines } = await api('/api/engines');
  const box = $('#dash-engines');
  limpar(box);
  engines.forEach((e) => {
    const linha = el('div', { class: 'engine-line' });
    linha.appendChild(el('span', {
      class: 'badge ' + (e.available ? 'b-good' : 'b-muted'),
    }, e.available ? 'ok' : 'fora'));
    linha.appendChild(el('span', { class: 'nome' }, e.slug));
    linha.appendChild(el('span', { class: 'muted small' }, `peso ${e.weight}`));
    linha.appendChild(el('span', { class: 'motivo' },
      e.available ? (e.version || '') : (e.unavailable_reason || 'indisponível')));
    box.appendChild(linha);
  });
}

$('#btn-scan').addEventListener('click', async (ev) => {
  ev.target.disabled = true;
  ev.target.textContent = 'Escaneando…';
  try {
    const r = await api('/api/scan', { method: 'POST', body: JSON.stringify({ full: false }) });
    toast(`Ciclo ${r.scan_id} concluído: ${r.files_scanned} arquivo(s) escaneado(s).`);
    await carregarTudo();
  } catch (e) {
    toast(e.message, true);
  } finally {
    ev.target.disabled = false;
    ev.target.textContent = 'Escanear agora';
  }
});

// ---------------------------------------------------------------- achados

async function carregarAchados() {
  const pendentes = $('#f-pendentes').checked ? '?pending=1' : '';
  const { verdicts } = await api('/api/verdicts' + pendentes);
  const lista = $('#lista-achados');
  limpar(lista);

  if (!verdicts || verdicts.length === 0) {
    lista.appendChild(el('div', { class: 'card empty' },
      pendentes ? 'Nenhum achado aguardando decisão.' : 'Nenhum achado registrado.'));
    return;
  }
  verdicts.forEach((v) => lista.appendChild(cardVeredito(v)));
}

function cardVeredito(v) {
  const card = el('div', { class: 'card verdict ' + v.level });

  const cab = el('div', { class: 'chart-head' });
  cab.appendChild(el('span', { class: 'badge ' + CLASSE_NIVEL[v.level] },
    ROTULO_NIVEL[v.level] || v.level));
  cab.appendChild(el('span', { class: 'muted small' }, `score ${v.score.toFixed(2)}`));
  cab.appendChild(el('span', { class: 'spacer' }));
  cab.appendChild(el('span', { class: 'muted small' }, fmtData(v.created_at)));
  card.appendChild(cab);

  card.appendChild(el('div', { class: 'path' }, v.file_path));

  const barra = el('div', { class: 'score-bar' });
  const preench = el('i');
  preench.style.width = Math.round(v.score * 100) + '%';
  barra.appendChild(preench);
  card.appendChild(barra);

  // Os votos SAO o veredito. Sem eles o usuario precisaria confiar cegamente.
  const t = el('table', { class: 'votes' });
  (v.votes || []).forEach((voto) => {
    const tr = el('tr');
    tr.appendChild(el('td', { class: 'eng' }, voto.engine));
    tr.appendChild(el('td', { class: 'calc' },
      `${voto.weight.toFixed(2)} × ${voto.confidence} = ${voto.effective_weight.toFixed(2)}`));
    tr.appendChild(el('td', {}, voto.rule));
    tr.appendChild(el('td', { class: 'muted' }, voto.category));
    t.appendChild(tr);
  });
  card.appendChild(t);

  if (v.abstentions && v.abstentions.length) {
    card.appendChild(el('p', { class: 'muted small' },
      `Abstenções: ${v.abstentions.join(', ')} — a cobertura deste ciclo foi reduzida.`));
  }
  if (v.clean_reason) {
    card.appendChild(el('p', { class: 'small c-good' },
      `Veto aplicado: ${v.clean_reason}. Este arquivo nunca será quarentenado.`));
  }
  if (v.action_taken && v.action_taken !== 'none') {
    const txt = v.action_error ? `${v.action_taken} — ${v.action_error}` : v.action_taken;
    card.appendChild(el('p', { class: 'small muted' }, `Ação: ${txt}`));
  }

  if (!v.acknowledged_by_user && v.level !== 'clean' && !v.clean_reason) {
    const acoes = el('div', { class: 'actions' });
    acoes.appendChild(botaoDecisao(v, 'quarantine', 'Quarentenar', 'btn danger'));
    acoes.appendChild(botaoDecisao(v, 'ignore', 'Ignorar uma vez', 'btn'));
    acoes.appendChild(botaoDecisao(v, 'whitelist', 'Adicionar à whitelist', 'btn'));
    card.appendChild(acoes);
  }
  return card;
}

function botaoDecisao(v, acao, rotulo, classe) {
  const b = el('button', { class: classe }, rotulo);
  b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      const r = await api(`/api/verdicts/${encodeURIComponent(v.verdict_id)}/decide`, {
        method: 'POST', body: JSON.stringify({ action: acao }),
      });
      if (acao === 'quarantine') {
        toast(`Quarentenado (ref ${r.quarantine_ref}). O arquivo continua restaurável.`);
      } else {
        toast('Decisão registrada.');
      }
      await carregarTudo();
    } catch (e) {
      toast(e.message, true);
      b.disabled = false;
    }
  });
  return b;
}

$('#f-pendentes').addEventListener('change', carregarAchados);

// ---------------------------------------------------------------- quarentena

async function carregarQuarentena() {
  const todos = $('#q-todos').checked ? '?all=1' : '';
  const { items } = await api('/api/quarantine' + todos);
  const tb = $('#tab-quar tbody');
  limpar(tb);

  if (!items || items.length === 0) {
    const tr = el('tr');
    tr.appendChild(el('td', { colspan: '6', class: 'empty' }, 'O cofre está vazio.'));
    tb.appendChild(tr);
    return;
  }

  items.forEach((it) => {
    const tr = el('tr');
    tr.appendChild(el('td', { class: 'path' }, it.Ref));
    tr.appendChild(el('td', { class: 'path' }, it.OriginalPath));
    tr.appendChild(el('td', {}, fmtData(it.QuarantinedAt)));
    tr.appendChild(el('td', {}, fmtDia(it.RetentionUntil)));

    const st = el('td');
    st.appendChild(el('span', {
      class: 'badge ' + (it.Status === 'quarantined' ? 'b-warn' : 'b-muted'),
    }, it.Status));
    tr.appendChild(st);

    const acoes = el('td');
    if (it.Status === 'quarantined') {
      const restaurar = el('button', { class: 'btn sm' }, 'Restaurar');
      restaurar.addEventListener('click', async () => {
        restaurar.disabled = true;
        try {
          const r = await api(`/api/quarantine/${encodeURIComponent(it.Ref)}/restore`, { method: 'POST' });
          toast(`Restaurado byte a byte em ${r.restored_to}`);
          await carregarTudo();
        } catch (e) {
          toast(e.message, true);
          restaurar.disabled = false;
        }
      });
      acoes.appendChild(restaurar);

      const purgar = el('button', { class: 'btn sm danger' }, 'Purgar');
      purgar.addEventListener('click', () => confirmarPurga(it));
      acoes.appendChild(purgar);
    }
    tr.appendChild(acoes);
    tb.appendChild(tr);
  });
}

$('#q-todos').addEventListener('change', carregarQuarentena);

function confirmarPurga(item) {
  const modal = $('#modal');
  $('#modal-title').textContent = 'Purgar definitivamente';
  $('#modal-body').textContent =
    `Isto apaga a cópia de ${item.OriginalPath} do cofre. É a única operação ` +
    `irreversível do SentinelHost: depois dela o arquivo não pode mais ser restaurado.`;
  $('#modal-input').value = '';
  modal.hidden = false;
  $('#modal-input').focus();

  $('#modal-ok').onclick = async () => {
    if ($('#modal-input').value !== 'purgar') {
      toast('Digite "purgar" para confirmar.', true);
      return;
    }
    try {
      await api(`/api/quarantine/${encodeURIComponent(item.Ref)}/purge`, {
        method: 'POST', body: JSON.stringify({ confirm: 'purgar' }),
      });
      toast('Item purgado definitivamente.');
      modal.hidden = true;
      await carregarTudo();
    } catch (e) {
      toast(e.message, true);
    }
  };
  $('#modal-cancel').onclick = () => { modal.hidden = true; };
}

// ---------------------------------------------------------------- engines

async function carregarEngines() {
  const { engines } = await api('/api/engines');
  const lista = $('#lista-engines');
  limpar(lista);

  engines.forEach((e) => {
    const card = el('div', { class: 'card' });

    const cab = el('div', { class: 'chart-head' });
    cab.appendChild(el('h2', {}, e.name || e.slug));
    cab.appendChild(el('span', {
      class: 'badge ' + (e.available ? 'b-good' : 'b-muted'),
    }, e.available ? 'disponível' : 'indisponível'));
    cab.appendChild(el('span', { class: 'spacer' }));
    cab.appendChild(el('span', { class: 'muted small' }, `peso ${e.weight}`));
    card.appendChild(cab);

    if (!e.available && e.unavailable_reason) {
      // FR-001: o motivo e obrigatorio. "Indisponivel" sozinho transforma um
      // problema resolvivel em misterio.
      card.appendChild(el('p', { class: 'small' }, e.unavailable_reason));
      const inst = el('button', { class: 'btn sm' }, 'Instalar no meu espaço');
      inst.addEventListener('click', async () => {
        inst.disabled = true;
        inst.textContent = 'Instalando…';
        try {
          await api(`/api/engines/${encodeURIComponent(e.slug)}/install`, { method: 'POST' });
          toast(`${e.slug} instalado.`);
          await carregarTudo();
        } catch (err) {
          toast(err.message, true);
          inst.disabled = false;
          inst.textContent = 'Instalar no meu espaço';
        }
      });
      card.appendChild(inst);
    } else if (e.version) {
      card.appendChild(el('p', { class: 'small muted' }, e.version));
    }

    const meta = el('div', { class: 'row3' });
    [
      ['Licença', e.license],
      ['Custo', e.cost],
      ['Assinaturas', fmtData(e.signatures_updated_at)],
      ['Última execução', fmtData(e.last_run_at)],
      ['Último status', e.last_run_status || '—'],
    ].forEach(([k, v]) => {
      const d = el('div');
      d.appendChild(el('small', { class: 'muted' }, k));
      d.appendChild(el('div', { class: 'small' }, String(v || '—')));
      meta.appendChild(d);
    });
    card.appendChild(meta);
    lista.appendChild(card);
  });
}

// ---------------------------------------------------------------- configuracao

let CFG = null;

async function carregarConfig() {
  const r = await api('/api/config');
  CFG = r.config;
  $('#cfg-path').textContent = 'Arquivo: ' + r.path;

  // Agendamento
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
    `# ciclo incremental (${cron.incremental})\n` +
    `0 * * * * sentinelhost scan --config ${cron.config_path} --quiet\n\n` +
    `# scan completo\n` +
    `${cron.full_cron} sentinelhost scan --config ${cron.config_path} --full --quiet\n\n` +
    `# ${cron.hint}`;

  // Alertas
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

  // Configuracoes
  $('#c-observacao').checked = !!CFG.general.observation_mode;
  $('#c-graca').value = CFG.general.grace_period_days;
  $('#c-confirmed').value = CFG.verdict.confirmed_at;
  $('#c-likely').value = CFG.verdict.likely_at;
  $('#c-suspicious').value = CFG.verdict.suspicious_at;
  $('#c-retencao').value = CFG.quarantine.retention_days;
  $('#c-autopurge').checked = !!CFG.quarantine.auto_purge;
  $('#c-whitelist').value = (CFG.verdict.whitelist || []).join('\n');
  $('#c-exclude').value = (CFG.limits.exclude || []).join('\n');
}

function renderHooks(hooks) {
  const box = $('#lista-hooks');
  limpar(box);
  hooks.forEach((h, i) => box.appendChild(cardHook(h, i)));
  if (hooks.length === 0) {
    box.appendChild(el('p', { class: 'muted small' }, 'Nenhum webhook cadastrado.'));
  }
}

function cardHook(h, i) {
  const card = el('div', { class: 'hook', dataset: { idx: String(i) } });

  const linha = el('div', { class: 'row2' });
  linha.appendChild(campo('ID', 'h-id', h.id));
  linha.appendChild(campo('URL', 'h-url', h.url));
  linha.appendChild(campo('Segredo (HMAC)', 'h-secret', h.secret, 'password'));
  card.appendChild(linha);

  const evs = el('fieldset', { class: 'niveis' });
  evs.appendChild(el('legend', {}, 'Eventos assinados'));
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

  const acoes = el('div', { class: 'actions' });
  const lblAtivo = el('label', { class: 'inline' });
  const cbAtivo = el('input', { type: 'checkbox', class: 'h-enabled' });
  cbAtivo.checked = !!h.enabled;
  lblAtivo.appendChild(cbAtivo);
  lblAtivo.appendChild(document.createTextNode(' habilitado'));
  acoes.appendChild(lblAtivo);

  const teste = el('button', { class: 'btn sm' }, 'Enviar teste');
  teste.addEventListener('click', () => testarWebhook(h.id, card));
  acoes.appendChild(teste);

  const remover = el('button', { class: 'btn sm danger' }, 'Remover');
  remover.addEventListener('click', () => card.remove());
  acoes.appendChild(remover);
  card.appendChild(acoes);

  card.appendChild(el('div', { class: 'result', hidden: 'hidden' }));
  return card;
}

function campo(rotulo, classe, valor, tipo = 'text') {
  const l = el('label', {}, rotulo);
  const i = el('input', { class: classe, type: tipo });
  i.value = valor || '';
  l.appendChild(i);
  return l;
}

$('#btn-add-hook').addEventListener('click', () => {
  $('#lista-hooks').appendChild(cardHook(
    { id: '', url: '', secret: '', events: ['verdict.confirmed'], enabled: true },
    $$('.hook').length));
});

// ---------------------------------------------------------------- salvamentos

async function salvar(patch, msgOK) {
  try {
    const r = await api('/api/config', { method: 'PUT', body: JSON.stringify(patch) });
    toast(msgOK);
    if (r.warnings && r.warnings.length) {
      r.warnings.forEach((a) => toast('Aviso — ' + a, true));
    }
    await carregarConfig();
  } catch (e) {
    toast(e.message, true);
  }
}

$('#btn-salvar-agenda').addEventListener('click', () => salvar({
  incremental: $('#s-incremental').value,
  full_cron: $('#s-full').value,
  signatures_cron: $('#s-sig').value,
  schedule_mode: $('#s-mode').value,
  nice: Number($('#s-nice').value),
  max_file_size_mb: Number($('#s-maxsize').value),
  engine_timeout: $('#s-timeout').value,
  batch_size: Number($('#s-batch').value),
  batch_pause: $('#s-pause').value,
}, 'Agendamento salvo. Vale a partir do próximo ciclo.'));

$('#btn-salvar-email').addEventListener('click', () => salvar({
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
}, 'Configuração de e-mail salva.'));

$('#btn-salvar-hooks').addEventListener('click', () => {
  const hooks = $$('.hook').map((card) => ({
    id: $('.h-id', card).value.trim(),
    url: $('.h-url', card).value.trim(),
    secret: $('.h-secret', card).value,
    enabled: $('.h-enabled', card).checked,
    events: $$('.h-ev', card).filter((cb) => cb.checked).map((cb) => cb.value),
  }));
  salvar({ webhooks: hooks }, 'Webhooks salvos.');
});

$('#btn-salvar-config').addEventListener('click', () => salvar({
  observation_mode: $('#c-observacao').checked,
  grace_period_days: Number($('#c-graca').value),
  confirmed_at: Number($('#c-confirmed').value),
  likely_at: Number($('#c-likely').value),
  suspicious_at: Number($('#c-suspicious').value),
  retention_days: Number($('#c-retencao').value),
  auto_purge: $('#c-autopurge').checked,
  whitelist: $('#c-whitelist').value.split('\n').map((s) => s.trim()).filter(Boolean),
  exclude: $('#c-exclude').value.split('\n').map((s) => s.trim()).filter(Boolean),
}, 'Configurações salvas.'));

// ---------------------------------------------------------------- testes

$('#btn-test-email').addEventListener('click', async (ev) => {
  const box = $('#res-email');
  ev.target.disabled = true;
  box.hidden = false;
  box.className = 'result';
  box.textContent = 'Enviando…';
  try {
    const r = await api('/api/alert/test', {
      method: 'POST', body: JSON.stringify({ channel: 'email' }),
    });
    // O erro REAL vai para a tela: descobrir que a hospedagem bloqueia a
    // porta 587 e o proposito inteiro deste botao.
    box.className = 'result ' + (r.ok ? 'ok' : 'bad');
    box.textContent = r.message + (r.error ? '\n' + r.error : '');
  } catch (e) {
    box.className = 'result bad';
    box.textContent = e.message;
  } finally {
    ev.target.disabled = false;
  }
});

async function testarWebhook(id, card) {
  const box = $('.result', card);
  box.hidden = false;
  box.className = 'result';
  box.textContent = 'Enviando…';
  try {
    const r = await api('/api/alert/test', {
      method: 'POST', body: JSON.stringify({ channel: 'webhook', id }),
    });
    box.className = 'result ' + (r.ok ? 'ok' : 'bad');
    let txt = r.message;
    if (r.response_body) txt += '\n\nresposta: ' + r.response_body;
    box.textContent = txt;
  } catch (e) {
    box.className = 'result bad';
    box.textContent = e.message;
  }
}

// ---------------------------------------------------------------- carga geral

async function carregarTudo() {
  const tarefas = [
    ['visão geral', carregarStatus],
    ['engines', carregarEnginesResumo],
    ['achados', carregarAchados],
    ['quarentena', carregarQuarentena],
    ['engines', carregarEngines],
    ['configuração', carregarConfig],
  ];
  // Uma area que falha nao pode apagar o painel inteiro: o usuario ainda
  // precisa ver as outras.
  for (const [nome, fn] of tarefas) {
    try {
      await fn();
    } catch (e) {
      if (e.message !== 'sessao expirada') {
        toast(`Não foi possível carregar ${nome}: ${e.message}`, true);
      }
    }
  }
}

bootstrap();
