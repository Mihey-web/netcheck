import './style.css';
import {RunCheck, CancelCheck, GetHistory, GetRun, GetConfig, SaveConfig, CurrentLang, SetLang, Version,
  ListFonts, FontCSS, ApplyWindowScale, Catalog, Presets, SetServices,
  RunSingle, MeasureSpeed,
  DeleteRuns, ClearHistory, SetTab as saveTab} from '../wailsjs/go/main/App';
import {EventsOn} from '../wailsjs/runtime/runtime';
import {t, pl, applyLang, getLang} from './i18n';
import {WorldMap} from './worldmap';

const LAYERS = ['gateway', 'dns', 'runet', 'global', 'blocked'];
const $ = id => document.getElementById(id);

const state = {
  cfg: null,          // config.Config (поля с заглавной буквы: Targets.Runet и т.д.)
  env: null,          // env.Snapshot
  report: null,       // runner.Report
  history: [],        // history.Entry[]
  version: '',
  running: false,
  canceling: false,   // нажали «Отменить», ждём, пока бэкенд дожуёт текущую пробу
  progress: null,     // {done, total} — счётчик «N из M» на кнопке
  configError: null,  // конфиг не прочитался (текст ошибки с бэкенда)
  doneLayers: new Set(),
  selectedAt: '',     // какой прогон сейчас показан (RFC3339)
  error: null,
  histError: null,    // ошибка операций с историей (ключ i18n) — живёт у панели истории
  fonts: null,        // установленные семейства, подгружаются при открытии настроек
  tab: 'report',      // активная вкладка: 'report' | 'services' | 'map'
  catalog: [],        // catalog.Item[] — справочник на текущем языке
  presets: {},        // имя набора → идентификаторы
  picked: new Set(),  // выбранные идентификаторы
  custom: [],         // {host, group}[] — цели, добавленные руками
  svcQuery: '',       // фильтр в поиске по сервисам
  // ── живая таблица ──
  // live — результаты в порядке прихода вместе со слоем, который назвал
  // бэкенд. Он знает слой точно, поэтому для свежего прогона фронтовая
  // догадка classifyResults не нужна вовсе.
  live: [],           // {layer, r}[]
  liveFor: '',        // какому прогону принадлежит live (startedAt)
  stick: true,        // держаться низа таблицы при добавлении строк
  // ── выдача по сервисам ──
  svcOpen: new Set(), // хосты раскрытых строк выдачи (живёт в сессии)
  speed: {},          // id сервиса → {phase:'measuring'} | {phase:'done', res}
  // точечная проверка своего сайта (§3)
  single: {running: false, host: '', report: null, errKey: null, errText: null, added: false},
};

// group — состояние текущей группы строк в живой таблице: её слой, первая
// строка (на ней подпись слоя и подсветка) и худший статус внутри.
let group = {layer: null, tr: null, worst: 'ok'};

/* ──────────────── утилиты ──────────────── */

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g,
    c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}

const pad = n => String(n).padStart(2, '0');

// Наносекунды → человеческое: <1000 мс → «N мс», иначе «N.N с».
function fmtDur(ns) {
  if (ns == null || !isFinite(ns)) return '—';
  const ms = ns / 1e6;
  if (ms < 1) return '<1 ' + t('unit.ms');
  if (ms < 1000) return Math.round(ms) + ' ' + t('unit.ms');
  return (ms / 1000).toFixed(1) + ' ' + t('unit.s');
}

// Время: сегодня — HH:MM, вчера — «вчера HH:MM», иначе DD.MM HH:MM.
function fmtWhen(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  const hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
  const now = new Date();
  const same = (a, b) => a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
  if (same(d, now)) return hm;
  const y = new Date(now); y.setDate(now.getDate() - 1);
  if (same(d, y)) return t('hist.yesterday') + ' ' + hm;
  return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + ' ' + hm;
}

function hostOf(u) {
  return String(u || '').replace(/^[a-z+.-]+:\/\//i, '').replace(/[/:?#].*$/, '');
}

// один ли это прогон: время из истории и из отчёта могут отличаться точностью
const sameRun = (a, b) => !!a && !!b && new Date(a).getTime() === new Date(b).getTime();

const stChip = s => s === 'ok' ? 'ok' : s === 'warn' ? 'warn' : s === 'skip' ? 'skip' : 'bad';
// Отсутствие статуса — это «не проверяли», а не «провал»: красить его
// красным значило бы придумывать результат там, где его нет.
const stCell = s => s === 'ok' ? 'ok' : s === 'warn' ? 'warn'
  : (s === 'skip' || !s) ? 'skip' : 'fail';

/* ──────────────── классификация результат→слой ──────────────── */

// makeClassifier — догадка «какому слою принадлежит результат» для отчётов,
// прочитанных из истории: в них слой не сохранён. У свежего прогона слой
// приходит с бэкенда, и сюда дело не доходит.
//
// Состояние (seenDNS) живёт внутри одного классификатора, поэтому его нельзя
// звать по одному результату из общей функции — только через свой экземпляр.
function makeClassifier() {
  const cfg = state.cfg || {};
  const tg = cfg.Targets || {};
  const runet = new Set(tg.Runet || []);
  const glob = new Set(tg.Global || []);
  const blocked = tg.Blocked || [];
  const dnsProbe = blocked[0] || 'youtube.com';
  const globalIP = (cfg.Ping && cfg.Ping.GlobalIP) || '1.1.1.1';
  // первые DNS/DoH-ответы по контрольному хосту принадлежат слою DNS,
  // повторные (в рамках проверки блокировок) — слою сервисов
  const seenDNS = {'DNS': false, 'DNS·DoH': false};

  return r => {
    const m = r.method || '';
    if (m === 'ping') return (r.target === globalIP) ? 'global' : 'gateway';
    if (m.startsWith('DNS')) {
      if (m === 'DNS·UDP') return 'dns';
      if (r.target === dnsProbe && !seenDNS[m]) { seenDNS[m] = true; return 'dns'; }
      return 'blocked';
    }
    if (m === 'HTTPS' || m === 'HTTP') {
      const h = hostOf(r.target);
      if (runet.has(h)) return 'runet';
      if (glob.has(h)) return 'global';
    }
    // контрольный SYN до опорного адреса — это проверка связности, а не сервис
    if (m.startsWith('TCP:') && String(r.target).split(':')[0] === globalIP) return 'gateway';
    return 'blocked';
  };
}

function classifyResults(results) {
  const cls = makeClassifier();
  const buckets = {gateway: [], dns: [], runet: [], global: [], blocked: []};
  for (const r of results || []) buckets[cls(r)].push(r);
  return buckets;
}

/* ──────────────── рендер ──────────────── */

function kv(k, v, vcls) {
  return `<div class="kv"><span class="k">${esc(k)}</span>` +
    `<span class="v${vcls ? ' ' + vcls : ''}">${v}</span></div>`;
}

function renderEnv() {
  const s = state.env;
  const dash = '<span class="dim">—</span>';
  let h = '';
  h += kv(t('env.net'), s && s.adapter ? esc(s.adapter) : dash);
  h += kv(t('env.gateway'), s && s.gateway ? esc(s.gateway) : dash);
  h += kv(t('env.ip'), s && s.ip ? esc(s.ip) : dash);
  h += `<div class="subhd">${esc(t('env.vpn'))}</div>`;

  const proxies = (s && s.proxies) || [];
  if (proxies.length) {
    for (const p of proxies) {
      const proto = p.proto || p.kind || '';
      const label = getLang() === 'ru' ? `${proto}-${t('env.proxy')}` : `${proto} ${t('env.proxy')}`;
      const val = p.active
        ? `${esc(p.addr || '')} · ${esc(t('val.active'))}`
        : esc(p.addr || '—');
      h += kv(label, val, p.active ? 'good' : 'dim');
    }
  } else {
    h += kv(getLang() === 'ru' ? 'VPN-' + t('env.proxy') : 'VPN ' + t('env.proxy'),
      esc(t('val.none')), 'dim');
  }

  if (s && s.systemProxyOn) {
    const addr = s.systemProxyAddr ? esc(s.systemProxyAddr) + ' · ' : '';
    h += kv(t('env.sysproxy'), addr + esc(t('val.on')), 'good');
  } else {
    // предупреждающий жёлтый только когда есть активный прокси, а системный выключен
    const hasActive = proxies.some(p => p.active && p.kind === 'listener');
    h += kv(t('env.sysproxy'), s ? esc(t('val.off')) : dash, s ? (hasActive ? 'warn' : 'dim') : 'dim');
  }

  const tun = (s && s.tunnels) || [];
  if (tun.length) {
    let val = esc(tun.join(', '));
    if (s.defaultViaTunnel) val += ' · ' + esc(t('env.defroute'));
    h += kv(t('env.tunnels'), val, 'good');
  } else {
    h += kv(t('env.tunnels'), s ? esc(t('val.none')) : dash, 'dim');
  }

  h += kv(t('env.tailscale'), s && s.tailscale ? esc(s.tailscale) : (s ? esc(t('val.none')) : dash),
    s && s.tailscale ? '' : 'dim');

  $('env-body').innerHTML = h;
}

function renderChain() {
  const statuses = {};
  const chain = state.report && (state.report.verdict?.chain?.length
    ? state.report.verdict.chain : state.report.layers);
  if (chain) for (const l of chain) statuses[l.layer] = l.status;

  let firstPending = null;
  if (state.running) {
    firstPending = LAYERS.find(l => !state.doneLayers.has(l)) ?? null;
  }

  const chips = LAYERS.map(l => {
    let cls = '';
    if (state.running) {
      if (state.doneLayers.has(l)) cls = 'done';
      else if (l === firstPending) cls = 'run';
    } else if (statuses[l]) {
      cls = stChip(statuses[l]);
    }
    return `<span class="chip${cls ? ' ' + cls : ''}"><i></i>${esc(t('layer.' + l))}</span>`;
  });
  $('chain').innerHTML = chips.join('<span class="arr">→</span>');
}

// Общий счёт прогона: сколько проверок прошло, сколько нет, и сколько
// сервисов в итоге работает. Вердикт словами объясняет причину, а этот
// ряд отвечает на «ну и как в целом» одним взглядом.
function renderTally() {
  const el = $('tally');
  const rep = state.report;
  if (!rep || state.running || state.error) {
    el.innerHTML = '';
    return;
  }
  const c = {ok: 0, warn: 0, fail: 0, skip: 0};
  for (const r of rep.results || []) c[r.status] = (c[r.status] || 0) + 1;
  const total = (rep.results || []).length;

  const svc = rep.services || [];
  const live = svc.filter(s => s.directOk).length;
  // Счётчик молча означал «напрямую», а читался как «у тебя работает 7 из 25».
  // У человека с включённым VPN это прямая дезинформация: его трафик идёт
  // через VPN, где открывается втрое больше. Раз замер через VPN сделан —
  // показываем оба числа и подписываем, какое из них какое.
  const viaVPN = svc.some(s => s.proxyTried) ? svc.filter(s => s.proxyOk).length : null;

  const cell = (cls, n, key) =>
    n ? `<span class="tc ${cls}"><b>${n}</b>${esc(t(key))}</span>` : '';

  let html =
    `<span class="tc tot"><b>${total}</b>${esc(pl(total, 'cnt.checks'))}</span>` +
    cell('ok', c.ok, 'tally.ok') +
    cell('warn', c.warn, 'tally.warn') +
    (c.fail ? `<span class="tc fail"><b>${c.fail}</b>${esc(pl(c.fail, 'cnt.fails'))}</span>` : '') +
    cell('skip', c.skip, 'tally.skip');
  if (svc.length) {
    html += `<span class="tc svc">${esc(t('tally.services'))} <b>${live}</b><i>/${svc.length}</i>` +
      (viaVPN === null ? '' : `<em>${esc(t('tally.direct'))}</em>`) + `</span>`;
    if (viaVPN !== null) {
      html += `<span class="tc svc"><b>${viaVPN}</b><i>/${svc.length}</i>` +
        `<em>${esc(t('tally.via_vpn'))}</em></span>`;
    }
  }
  el.innerHTML = html;
}

// renderVerdict — вердикт целиком: текст, карточка «свой сайт» и список
// сервисов. Текстовая часть вынесена отдельно, чтобы ранние выходы
// (идёт прогон / ошибка / пусто) не пропускали список и карточку.
function renderVerdict() {
  renderVerdictText();
  renderSingleCard();
  renderSvcList();
}

function renderVerdictText() {
  renderTally();
  const meta = $('verdict-meta');
  const vt = $('vtext');
  const vw = $('vwarns');
  const rep = state.report;

  if (state.running) {
    meta.textContent = '';
    vt.innerHTML = `<p class="dim">${esc(t('verdict.running'))}</p>`;
    vw.innerHTML = '';
    return;
  }
  if (state.error) {
    meta.textContent = '';
    vt.innerHTML = `<p class="verr">${esc(t('err.run'))}: ${esc(state.error)}</p>`;
    vw.innerHTML = '';
    return;
  }
  if (!rep) {
    meta.textContent = '';
    vt.innerHTML = `<p class="dim">${esc(t('verdict.empty'))}</p>`;
    vw.innerHTML = '';
    return;
  }
  meta.textContent = fmtWhen(rep.startedAt) + ' · ' + fmtDur(rep.duration);
  const lines = (rep.verdict && rep.verdict.lines) || [];
  // Когда есть список сервисов, сводная строка — заголовок над ним,
  // остальные строки — мелче. Старый отчёт без services рендерится как раньше.
  const hasSvc = !!(rep.verdict && rep.verdict.services && rep.verdict.services.length);
  vt.innerHTML = !lines.length
    ? `<p class="dim">—</p>`
    : hasSvc
      ? `<p class="vhead">${esc(lines[0])}</p>` +
        lines.slice(1).map(l => `<p class="vrest">${esc(l)}</p>`).join('')
      : lines.map(l => `<p>${esc(l)}</p>`).join('');
  const warns = (rep.verdict && rep.verdict.warnings) || [];
  vw.innerHTML = warns.map(w => `<div class="vnote">⚠ ${esc(w)}</div>`).join('');
}

/* ──────────────── выдача по сервисам (§2) ──────────────── */

// порядок показа: сломанные сверху, работающие в конце
// сломанные сверху, работающие — вниз: «работает через VPN» для человека
// такой же рабочий сервис, как и открывающийся напрямую
const ST_ORDER = {down: 0, need_vpn: 1, geo: 2, challenge: 3, unknown: 4, ok_via_vpn: 5, ok: 6};

// сервис из справочника по хосту: там живут имя и speedUrl
const catBy = host => state.catalog.find(s => s.host === host);

// fmt — подстановка аргументов в строку словаря по местам %s (по порядку)
const fmt = (key, ...args) => args.reduce((s, a) => s.replace('%s', a), t(key));

// Мбит/с: один знак после запятой, локале-нейтрально (точка)
const fmtMbps = v => (v == null || !isFinite(v)) ? '—' : Number(v).toFixed(1);

// speedResultHTML — итог замера в строке сервиса; err — только в title
function speedResultHTML(res) {
  if (!res || res.status === 'error') {
    return `<span class="sres bad" title="${esc((res && res.err) || '')}">${esc(t('speed.error'))}</span>`;
  }
  let txt, cls;
  if (res.status === 'slow' && !(res.serviceMbps > 0)) {
    // Ноль — не «нет данных», а самый сильный из возможных результатов:
    // канал качает, а с CDN сервиса не приходит ничего.
    txt = fmt('speed.dead', fmtMbps(res.refMbps));
    cls = 'bad';
  } else if (res.status === 'slow') {
    txt = fmt('speed.slow', String(Math.round(res.refMbps / res.serviceMbps)),
      fmtMbps(res.serviceMbps), fmtMbps(res.refMbps));
    cls = 'bad';
  } else if (res.status === 'maybe_slow') {
    txt = fmt('speed.maybe_slow', fmtMbps(res.serviceMbps), fmtMbps(res.refMbps));
    cls = 'warn';
  } else {
    txt = fmt('speed.normal', fmtMbps(res.serviceMbps), fmtMbps(res.refMbps));
    cls = 'good';
  }
  if (res.proxyServiceMbps) txt += ' ' + fmt('speed.via_vpn', fmtMbps(res.proxyServiceMbps));
  return `<span class="sres ${cls}">${esc(txt)}</span>`;
}

// speedSlotHTML — содержимое блока замера: кнопка / «идёт замер…» / результат
function speedSlotHTML(id) {
  const sp = state.speed[id];
  if (sp && sp.phase === 'measuring') {
    return `<span class="smeasuring">${esc(t('speed.measuring'))}</span>`;
  }
  return `<button class="smeasure" data-id="${esc(id)}">${esc(t('speed.button'))}</button>` +
    (sp && sp.res ? speedResultHTML(sp.res) : '');
}

// refreshSpeedSlots — обновить все места, где виден замер этого сервиса
// (строка списка и карточка «свой сайт»), не пересобирая список: пересборка
// сбросила бы прокрутку и раскрытые строки под руками у человека.
function refreshSpeedSlots(id) {
  document.querySelectorAll(`.sspeed[data-id="${CSS.escape(id)}"]`)
    .forEach(el => { el.innerHTML = speedSlotHTML(id); });
}

// measureSpeed — замер по кнопке (§4). Результат живёт в сессии.
async function measureSpeed(id) {
  if (!id || (state.speed[id] && state.speed[id].phase === 'measuring')) return;
  state.speed[id] = {phase: 'measuring'};
  refreshSpeedSlots(id);
  let res;
  try {
    res = await MeasureSpeed(id);
  } catch (e) {
    console.error(e);
    res = {status: 'error', err: (e && e.message) ? e.message : String(e)};
  }
  state.speed[id] = {phase: 'done', res};
  refreshSpeedSlots(id);
}

// svcProbesHTML — пробы самого сервиса в раскрытой строке: тот же материал,
// что в общей таблице «Технические детали», но отфильтрованный по хосту и
// компактно: метод, статус, деталь, время. Прямые пробы и пробы через VPN
// разведены подписями, когда есть и те и другие.
function svcProbesHTML(host, rep) {
  const all = ((rep && rep.results) || []).filter(r => hostOf(r.target) === host);
  if (!all.length) return '';
  const direct = all.filter(r => r.path !== 'proxy');
  const proxy = all.filter(r => r.path === 'proxy');
  const row = r => {
    const stc = stCell(r.status);
    const why = esc(probeWhy(r));
    return `<tr><td class="pm">${esc(r.method)}</td>` +
      `<td class="pst"><span class="st ${stc}">${stc.toUpperCase()}</span></td>` +
      // title дублирует деталь целиком — как в общей таблице, ellipsis прячет суть
      `<td class="pwhy"${why ? ` title="${why}"` : ''}>${why}</td>` +
      `<td class="pms">${fmtDur(r.latency)}</td></tr>`;
  };
  // подписи «напрямую/через VPN» нужны, только когда есть оба вида проб
  const section = (rows, key) => !rows.length ? '' :
    (proxy.length ? `<tr class="pgrp"><td colspan="4">${esc(t(key))}</td></tr>` : '') +
    rows.map(row).join('');
  return `<div class="sprobes"><table>` +
    section(direct, 'tally.direct') + section(proxy, 'tally.via_vpn') +
    `</table></div>`;
}

// svcRowHTML — одна строка выдачи: значок статуса, имя, короткий статус;
// раскрытая часть — причина, совет, пробы сервиса и замер скорости.
// opts.open — раскрыта сразу, opts.add — с кнопкой «добавить в мой список»,
// opts.report — откуда брать пробы (карточка своего сайта живёт не в state.report).
function svcRowHTML(s, opts = {}) {
  const st = s.status || 'unknown';
  const it = catBy(s.host);
  const name = (it && it.name) || s.host;
  const open = opts.open || state.svcOpen.has(s.host);
  // Замер скорости осмыслен только там, где сервис открывается напрямую:
  // это и есть вопрос «не душат ли меня». Если напрямую он не открывается
  // вовсе, мерить нечего — там и так ноль, и цифра лишь запутала бы.
  const spid = (it && it.speedUrl && st === 'ok') ? it.id : null;
  let detail = '';
  if (s.reason) detail += `<p class="sreason">${esc(s.reason)}</p>`;
  if (s.advice) detail += `<p class="sadvice">${esc(t(s.advice))}</p>`;
  detail += svcProbesHTML(s.host, opts.report || state.report);
  if (spid) detail += `<div class="sspeed" data-id="${esc(spid)}">${speedSlotHTML(spid)}</div>`;
  if (opts.add) detail += `<button class="sadd">${esc(t('single.add'))}</button>`;
  return `<div class="srow s-${esc(st)}${open ? ' open' : ''}" data-host="${esc(s.host)}">` +
    `<div class="shead"><i class="sic"></i>` +
    `<span class="sname">${esc(name)}</span>` +
    (name !== s.host ? `<span class="shost">${esc(s.host)}</span>` : '') +
    `<span class="sst">${esc(t('st.' + st))}</span>` +
    `<span class="scaret">${open ? '▴' : '▾'}</span></div>` +
    `<div class="sdetail${open ? '' : ' hidden'}">${detail}</div></div>`;
}

// toggleSvcRow — раскрыть/свернуть строку прямо в DOM: пересборка списка
// ради одного клика сбрасывала бы прокрутку. Набор открытых хостов
// запоминается, чтобы пережить перерисовку.
function toggleSvcRow(row) {
  const open = !row.classList.contains('open');
  row.classList.toggle('open', open);
  row.querySelector('.sdetail').classList.toggle('hidden', !open);
  const c = row.querySelector('.scaret');
  if (c) c.textContent = open ? '▴' : '▾';
  if (open) state.svcOpen.add(row.dataset.host);
  else state.svcOpen.delete(row.dataset.host);
}

function renderSvcList() {
  const el = $('svclist');
  const rep = state.report;
  const svcs = (!state.running && !state.error && rep && rep.verdict && rep.verdict.services) || [];
  if (!svcs.length) { el.innerHTML = ''; return; } // фолбэк: старый отчёт без services
  // сортировка стабильная: внутри одного статуса — порядок справочника
  const rows = [...svcs].sort((a, b) =>
    (ST_ORDER[a.status] ?? 9) - (ST_ORDER[b.status] ?? 9));
  // Строка контекста: без неё список читается двусмысленно — «работает
  // через VPN» непонятно, работает ли ПРЯМО СЕЙЧАС. Показываем только
  // когда VPN вообще есть: иначе это шум.
  const v = rep.verdict;
  const hasVPN = v.vpnCoversBrowser ||
    (rep.env && ((rep.env.proxies && rep.env.proxies.length) ||
      (rep.env.tunnels && rep.env.tunnels.length) || rep.env.defaultViaTunnel));
  const ctx = hasVPN
    ? `<p class="svcctx ${v.vpnCoversBrowser ? 'on' : 'off'}">` +
      esc(t(v.vpnCoversBrowser ? 'vpnctx.on' : 'vpnctx.off')) + '</p>'
    : '';
  el.innerHTML = ctx + rows.map(s => svcRowHTML(s)).join('');
}

// worseOf — худший из двух статусов; им красится вся группа слоя.
const worseOf = (a, b) =>
  a === 'fail' || b === 'fail' ? 'fail' : (a === 'warn' || b === 'warn' ? 'warn' : 'ok');

const layerName = l => l === 'blocked' ? t('tlayer.blocked') : t('layer.' + l);

// probeWhy — деталь пробы для колонки результата: текст ошибки, иначе
// полученные адреса. Общая для большой таблицы и проб в строке сервиса —
// один источник правды на оба места.
function probeWhy(r) {
  if (r.detail) return r.detail;
  if (r.ips && r.ips.length) return r.ips.join(', ');
  return '';
}

// rowHTML — одна строка результата без подписи слоя: подпись живёт
// на первой строке группы и проставляется отдельно.
function rowHTML(r) {
  const tgt = esc(r.method === 'HTTPS' || r.method === 'HTTP' ? hostOf(r.target) : r.target);
  const isProxy = r.path === 'proxy';
  const pathTxt = esc(isProxy ? t('path.proxy') : t('path.direct'));
  const stc = stCell(r.status);
  const why = esc(probeWhy(r));
  return `<td class="layer"></td>` +
    `<td class="tgt">${tgt}</td>` +
    `<td class="mth">${esc(r.method)}</td>` +
    `<td class="${isProxy ? 'path px' : 'path'}">${pathTxt}</td>` +
    `<td class="ms">${fmtDur(r.latency)}</td>` +
    // title дублирует detail целиком: ellipsis прячет самое информативное поле
    `<td class="res"${why ? ` title="${why}"` : ''}><span class="st ${stc}">${stc.toUpperCase()}</span>` +
    (why ? ` <span class="why">${why}</span>` : '') + `</td>`;
}

// appendRow — дописывает строку в конец таблицы, заводя новую группу, когда
// сменился слой. Ровно этим таблица и заполняется по ходу прогона.
function appendRow(layer, r) {
  const tb = $('tbody');
  const empty = tb.querySelector('.empty-cell');
  if (empty) tb.innerHTML = '';

  const tr = document.createElement('tr');
  tr.innerHTML = rowHTML(r);
  if (layer !== group.layer) {
    group = {layer, tr, worst: 'ok'};
    tr.classList.add('grp');
    tr.firstElementChild.textContent = layerName(layer);
  }
  tb.appendChild(tr);

  const worst = worseOf(group.worst, r.status === 'skip' ? 'ok' : r.status);
  if (worst !== group.worst && group.tr) {
    group.worst = worst;
    group.tr.classList.toggle('badgrp', worst === 'fail');
    group.tr.classList.toggle('warngrp', worst === 'warn');
  }
}

// stickBottom — таблица едет за новыми строками, но только пока пользователь
// сам не отлистал вверх: драться с ним за прокрутку она не должна.
function stickBottom() {
  const bd = $('tbody').closest('.bd');
  if (!bd || !state.stick) return;
  bd.scrollTop = bd.scrollHeight;
}

function tableMeta(total, layers) {
  $('tests-meta').textContent =
    `${total} ${pl(total, 'cnt.checks')} · ${layers} ${pl(layers, 'cnt.layers')}`;
}

// clearTable — таблица без данных: заглушка и пустая мета.
function clearTable(msg) {
  group = {layer: null, tr: null, worst: 'ok'};
  $('tbody').innerHTML = `<tr><td colspan="6" class="empty-cell">${esc(msg)}</td></tr>`;
  $('tests-meta').textContent = '';
}

function renderTable() {
  const rep = state.report;
  if (state.running) return; // во время прогона таблицу ведёт appendRow
  if (!rep || !rep.results || !rep.results.length) {
    // Прогон оборвался ошибкой, но часть проб успела отработать. Стирать
    // их и писать «нет данных» — значит выбросить единственное, по чему
    // видно, на чём именно всё встало.
    if (state.live.length) {
      tableMeta(state.live.length, new Set(state.live.map(x => x.layer)).size);
      return;
    }
    clearTable(t('table.empty'));
    return;
  }

  // У свежего прогона слои известны точно — берём их, а не догадку по методу.
  // Заодно строки остаются на тех же местах, где их видел человек во время
  // прогона: пересборка в конце ничего не переставляет.
  // Живые строки уже стоят в DOM и уже правильные — пересобирать их заново
  // значит обнулить прокрутку ровно в момент, когда человек дочитывает
  // последний слой. Обновляем только счётчик.
  if (sameRun(state.liveFor, rep.startedAt) && state.live.length >= rep.results.length) {
    tableMeta(state.live.length, new Set(state.live.map(x => x.layer)).size);
    stickBottom();
    return;
  }

  const buckets = classifyResults(rep.results);
  const rows = LAYERS.flatMap(l => buckets[l].map(r => ({layer: l, r})));

  group = {layer: null, tr: null, worst: 'ok'};
  $('tbody').innerHTML = '';
  const seen = new Set();
  for (const {layer, r} of rows) { seen.add(layer); appendRow(layer, r); }
  tableMeta(rows.length, seen.size);
}

function renderHistory() {
  const bd = $('hist-body');
  const h = state.history || [];
  const panel = bd.closest('.hist');
  if (panel) panel.classList.toggle('busy', state.running);
  $('hist-clear').classList.toggle('hidden', !h.length);
  // ошибка истории показывается здесь же, у панели, — вердикт она не трогает
  const errH = state.histError
    ? `<div class="hist-err">${esc(t(state.histError))}</div>` : '';
  if (!h.length) {
    bd.innerHTML = errH + `<div class="empty">${esc(t('hist.empty'))}</div>`;
    return;
  }
  const tip = state.running ? t('hist.busy') : t('hist.open');
  bd.innerHTML = errH + h.map(e => {
    const cls = stChip(e.status);
    const sel = sameRun(e.at, state.selectedAt) ? ' cur' : '';
    return `<div class="hrow ${cls}${sel}" data-at="${esc(e.at)}" title="${esc(tip)}">` +
      `<span class="t">${esc(fmtWhen(e.at))}</span>` +
      `<span class="s">${esc(e.summary || '')}</span>` +
      `<button class="hdel" title="${esc(t('hist.del'))}">✕</button></div>`;
  }).join('');
  bd.querySelectorAll('.hrow').forEach(row => {
    row.addEventListener('click', async () => {
      if (state.running) return;
      // Битая запись раньше «не работала» молча: loadRun возвращал false,
      // и клик выглядел как зависание. Теперь об этом сказано у панели.
      state.histError = null;
      if (!await loadRun(row.dataset.at)) {
        state.histError = 'hist.err.load';
        renderHistory();
      }
    });
    row.querySelector('.hdel').addEventListener('click', e => {
      e.stopPropagation(); // иначе удаление заодно откроет удаляемый прогон
      if (!state.running) queueHist(() => removeRuns([row.dataset.at]));
    });
  });
}

// removeRuns — удаление прогонов: выбранных поимённо либо (пустой список)
// всей истории целиком. Открытый на экране прогон, если он удалён, уходит
// вместе с записью — показывать отчёт, которого больше нет, нечестно.
// histOp — очередь операций над историей. Каждый клик по крестику запускал
// свой независимый цикл «прочитать файл — изменить — записать», и два клика
// подряд затирали друг друга: удалённая запись возвращалась.
let histOp = Promise.resolve();
const queueHist = fn => (histOp = histOp.then(fn, fn));

async function removeRuns(ats) {
  // ошибка идёт в своё поле: писать её в state.error значило бы стереть
  // вердикт и показать «Ошибку прогона», которой не было
  state.histError = null;
  try {
    if (ats === null) await ClearHistory();
    else await DeleteRuns(ats);
  } catch (e) {
    console.error(e);
    state.histError = 'hist.err';
  }
  try { state.history = await GetHistory() || []; } catch (e) { console.error(e); }
  const gone = ats === null || ats.some(at => sameRun(at, state.selectedAt));
  if (gone) {
    state.report = null;
    state.selectedAt = '';
    state.live = [];
    state.liveFor = '';
  }
  renderAll();
}

// Подтверждение прямо на кнопке: второй клик по «Точно?» стирает историю.
// Модалка ради одного вопроса — лишняя, а спрашивать надо: отменить нельзя.
let clearArmed = false;
let armedAt = 0;

// armCooldown — сколько кнопка не принимает второй клик после взвода.
// Без этой паузы двойной клик — обычная привычка в десктопных программах —
// стирал всю историю за один жест: первое нажатие взводило, второе тут же
// подтверждало, и прочитать вопрос человек не успевал.
const armCooldown = 400;

function armClear(on) {
  clearArmed = on;
  armedAt = on ? Date.now() : 0;
  const b = $('hist-clear');
  b.classList.toggle('armed', on);
  b.textContent = on
    ? t('hist.confirm.ok') + ' ' + (state.history || []).length
    : t('hist.clear');
  b.title = on ? t('hist.confirm.all').replace('%n',
    `${(state.history || []).length} ${pl((state.history || []).length, 'cnt.runs')}`)
    : t('hist.clear.title');
}

// progressText — подпись под кнопкой во время прогона: счётчик «N из M»,
// пока он не пришёл — просто «идёт проверка…».
function progressText() {
  const p = state.progress;
  if (!p || !p.total) return t('btn.sub.running');
  return t('btn.progress').replace('%n', p.done).replace('%t', p.total);
}

function updateButton() {
  const btn = $('btn-run');
  // Во время прогона кнопка живёт: она превращается в «Отменить».
  // Гаснет она только после нажатия отмены — второй раз отменять нечего.
  // Во время точечной проверки бэкенд занят — общий прогон не стартует,
  // и делать вид кнопкой, что стартует, не надо.
  btn.disabled = state.canceling || state.single.running;
  // поле «свой сайт» заблокировано на время общего прогона (и наоборот)
  $('single-host').disabled = state.running;
  $('single-btn').disabled = state.running || state.single.running;
  btn.classList.toggle('cancel', state.running);
  // Настройки посреди прогона меняют язык и перечитывают конфиг, а это
  // ломает состояние живой таблицы: половина строк остаётся на прежнем
  // языке, вторая приходит на новом.
  $('gear').disabled = state.running;
  $('btn-label').textContent = !state.running ? t('btn.run')
    : state.canceling ? t('btn.canceling') : t('btn.cancel');
  const last = (state.history || [])[0];
  $('btn-sub').textContent = state.running
    ? progressText()
    : (last ? `${t('btn.lastrun')} — ${fmtWhen(last.at)} · ${fmtDur(last.duration)}`
            : t('btn.norun'));
}

// renderConfigError — тихая строка под кнопкой: конфиг не прочитался,
// прогон идёт с настройками по умолчанию. Вердикт она не трогает.
function renderConfigError() {
  const el = $('cfg-err');
  el.classList.toggle('hidden', !state.configError);
  el.textContent = state.configError ? t('cfg.err') : '';
  el.title = state.configError || '';
}

function updateSubline() {
  const v = state.version ? ' · ' + state.version : '';
  $('subline').textContent = t('app.tagline') + v;
}

/* ──────────────── вкладки ──────────────── */

const TABS = ['report', 'services', 'map'];

function setTab(tab) {
  state.tab = tab;
  for (const name of TABS) {
    $('tab-' + name).classList.toggle('on', tab === name);
    $('view-' + name).classList.toggle('hidden', tab !== name);
  }
  // Пока вкладка скрыта, у контейнера нулевая высота и прокрутка стоит
  // в начале — при возврате таблица показывала бы шлюз вместо последних строк.
  if (tab === 'report') requestAnimationFrame(stickBottom);
  // пока вкладка скрыта, у холста нулевой размер — перерисовываем при показе
  if (tab === 'map' && worldMap) requestAnimationFrame(() => worldMap.render());
  saveTab(tab).catch(e => console.error(e));
}

// вкладка «Карта» существует, только пока карта включена в настройках
function updateTabs() {
  const on = !state.cfg || !state.cfg.Map || state.cfg.Map.Enabled !== false;
  $('tab-map').classList.toggle('hidden', !on);
  if (!on && state.tab === 'map') setTab('report');
}

/* ──────────────── вкладка «Сервисы» ──────────────── */

// Загружаем справочник и текущий выбор. Справочник приходит уже на нужном
// языке, поэтому при смене языка его надо перечитать.
async function loadCatalog() {
  const [items, presets] = await Promise.all([Catalog(), Presets()]);
  state.catalog = items || [];
  state.presets = presets || {};
  const sel = (state.cfg && state.cfg.Services) || {};
  state.picked = new Set(sel.Enabled || []);
  state.custom = (sel.Custom || []).map(c => ({host: c.host, group: c.group}));
}

// Сохраняем сразу: отдельной кнопки «применить» нет, чтобы выбор нельзя было
// потерять, уйдя на другую вкладку.
async function persistServices() {
  await SetServices([...state.picked], state.custom);
  state.cfg = await GetConfig();
}

// persistAndRender — сохранить выбор и перерисовать. Раньше падение
// SetServices оставляло промис без catch, а галочки — в состоянии, которого
// нет в конфиге; теперь при ошибке выбор откатывается к сохранённому.
async function persistAndRender() {
  try {
    await persistServices();
  } catch (e) {
    console.error(e);
    try { await loadCatalog(); } catch (e2) { console.error(e2); }
  }
  renderServices();
}

function svcMatches(host, name, note) {
  const q = state.svcQuery.trim().toLowerCase();
  if (!q) return true;
  return (host + ' ' + name + ' ' + note).toLowerCase().includes(q);
}

function renderServices() {
  const total = state.catalog.length + state.custom.length;
  const picked = state.picked.size + state.custom.length;
  $('svc-count').textContent = t('svc.selected').replace('%n', picked).replace('%t', total);

  let html = '';
  for (const g of ['runet', 'global', 'blocked', 'geo']) {
    const rows = [];
    for (const s of state.catalog) {
      if (s.group !== g || !svcMatches(s.host, s.name, s.note)) continue;
      const on = state.picked.has(s.id);
      rows.push(
        `<label class="svc${on ? ' on' : ''}">` +
        `<input type="checkbox" data-id="${esc(s.id)}"${on ? ' checked' : ''}/>` +
        `<span class="n">${esc(s.name)}</span>` +
        `<span class="h">${esc(s.host)}</span>` +
        (s.note ? `<span class="q">${esc(s.note)}</span>` : '') +
        `</label>`);
    }
    // свои цели живут в той группе, куда их положил пользователь
    state.custom.forEach((c, i) => {
      if (c.group !== g || !svcMatches(c.host, '', '')) return;
      rows.push(
        `<label class="svc on own">` +
        `<input type="checkbox" checked disabled/>` +
        `<span class="n">${esc(c.host)}</span>` +
        `<span class="h">${esc(t('svc.own'))}</span>` +
        `<button class="svc-del" data-idx="${i}" title="${esc(t('svc.remove'))}">✕</button>` +
        `</label>`);
    });
    if (!rows.length) continue;
    html +=
      `<div class="svc-grp">` +
      `<h4>${esc(t('grp.' + g))}<i>${esc(t('grp.' + g + '.hint'))}</i>` +
      `<button class="svc-all" data-grp="${g}">${esc(t('svc.preset.all'))}</button>` +
      `<button class="svc-all" data-grp="${g}" data-off="1">${esc(t('svc.preset.none'))}</button>` +
      `</h4><div class="svc-list">${rows.join('')}</div></div>`;
  }
  if (!html) html = `<div class="empty">${esc(t('svc.none_found'))}</div>`;
  else if (picked === 0) html = `<div class="empty warn">${esc(t('svc.nothing'))}</div>` + html;
  $('svc-groups').innerHTML = html;

  $('svc-groups').querySelectorAll('input[data-id]').forEach(el => {
    el.addEventListener('change', () => {
      if (el.checked) state.picked.add(el.dataset.id);
      else state.picked.delete(el.dataset.id);
      persistAndRender();
    });
  });
  $('svc-groups').querySelectorAll('.svc-all').forEach(btn => {
    btn.addEventListener('click', () => {
      for (const s of state.catalog) {
        if (s.group !== btn.dataset.grp || !svcMatches(s.host, s.name, s.note)) continue;
        if (btn.dataset.off) state.picked.delete(s.id);
        else state.picked.add(s.id);
      }
      persistAndRender();
    });
  });
  $('svc-groups').querySelectorAll('.svc-del').forEach(btn => {
    btn.addEventListener('click', e => {
      e.preventDefault();
      state.custom.splice(Number(btn.dataset.idx), 1);
      persistAndRender();
    });
  });
}

async function applyPreset(name) {
  if (name === 'none') state.picked = new Set();
  else if (name === 'all') state.picked = new Set(state.catalog.map(s => s.id));
  else state.picked = new Set(state.presets[name] || []);
  await persistAndRender();
}

// hostOk — грубая проверка имени хоста: латиница/цифры, точки и дефисы,
// метка не начинается и не кончается дефисом.
const hostOk = h =>
  /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(h);

// showSvcErr — ошибка под формой добавления; null прячет её
function showSvcErr(key) {
  const el = $('svc-err');
  el.textContent = key ? t(key) : '';
  el.classList.toggle('hidden', !key);
}

async function addCustomTarget() {
  const raw = $('svc-host').value.trim()
    .replace(/^[a-z+.-]+:\/\//i, '').replace(/\/.*$/, '');
  if (!raw) return;
  // Молча чистить поле при опечатке — значит делать вид, что цель добавлена.
  // Кириллический домен просим ввести в punycode, остальное — поправить.
  if (!hostOk(raw)) {
    showSvcErr(/[^\x00-\x7f]/.test(raw) ? 'svc.err.idn' : 'svc.err.host');
    return;
  }
  showSvcErr(null);
  const group = $('svc-group').value;
  // уже есть в справочнике — не плодим дубль, просто отмечаем
  const known = state.catalog.find(s => s.host === raw);
  if (known) state.picked.add(known.id);
  else if (!state.custom.some(c => c.host === raw)) state.custom.push({host: raw, group});
  $('svc-host').value = '';
  await persistAndRender();
}

/* ──────────────── карта ──────────────── */

function geoLabel(info) {
  const parts = [];
  if (info.city) parts.push(info.city);
  if (info.country) parts.push(info.country);
  else if (info.countryCode) parts.push(info.countryCode);
  return parts.join(', ') || info.ip || '?';
}

function renderMapSummary(routes, geoProxy) {
  const el = $('map-sum');
  if (!routes.length) { el.innerHTML = ''; return; }
  const done = routes.filter(r => r.reached).length;
  const cntCls = done === routes.length ? 'good' : done === 0 ? 'bad' : 'warn';
  let h = `<span><span class="k">${esc(t('map.sum.reached'))}</span>` +
    `<b class="${cntCls}">${done}/${routes.length}</b></span>`;

  // Кто именно оказался последним ответившим — самое полезное на этой
  // вкладке: одно имя объясняет сразу десяток оборвавшихся маршрутов.
  const owners = new Map();
  for (const r of routes) {
    if (r.reached || !r.break) continue;
    const who = r.break.org ? `AS${r.break.asn} ${r.break.org}` : r.break.ip;
    owners.set(who, (owners.get(who) || 0) + 1);
  }
  const top = [...owners.entries()].sort((a, b) => b[1] - a[1])[0];
  if (top) {
    h += `<span><span class="k">${esc(t('map.sum.brokeAt'))}</span>` +
      `<b class="bad">${esc(top[0])}</b></span>`;
  }
  const home = routes.find(r => r.home);
  if (home) {
    h += `<span><span class="k">${esc(t('map.sum.from'))}</span>` +
      `<b class="hud">${esc(home.home)}</b></span>`;
  }
  if (geoProxy) {
    const c = geoProxy.country || geoProxy.countryCode || '?';
    h += `<span><span class="k">${esc(t('map.sum.exit'))}</span><b class="hud">${esc(c)}</b></span>`;
  }
  el.innerHTML = h;
}

// Карта живёт в отдельном модуле: настоящая география Natural Earth на холсте,
// три стиля на выбор (вращающийся глобус, страны с границами, точечная матрица).
let worldMap = null;

const MAP_STYLES = {'ms-globe': 'globe', 'ms-countries': 'countries', 'ms-dots': 'dots'};

function initMap() {
  worldMap = new WorldMap($('map-canvas'), $('map-overlay'));
  for (const [id, st] of Object.entries(MAP_STYLES)) {
    $(id).addEventListener('click', () => {
      setMapStyle(st);
      // выбор запоминается между запусками
      if (state.cfg) {
        state.cfg.Map = Object.assign({}, state.cfg.Map, {Style: st});
        SaveConfig(state.cfg).catch(e => console.error(e));
      }
    });
  }
  // тумблер авто-вращения (ручное кручение мышью и колесом работает всегда)
  $('ms-spin').addEventListener('click', () => {
    setMapSpin(!worldMap.autoSpin);
    if (state.cfg) {
      state.cfg.Map = Object.assign({}, state.cfg.Map, {Spin: worldMap.autoSpin});
      SaveConfig(state.cfg).catch(e => console.error(e));
    }
  });

  const cfgMap = (state.cfg && state.cfg.Map) || {};
  const saved = cfgMap.Style;
  setMapStyle(Object.values(MAP_STYLES).includes(saved) ? saved : 'globe');
  setMapSpin(cfgMap.Spin !== false);
}

function setMapSpin(on) {
  worldMap.setSpin(on);
  $('ms-spin').classList.toggle('off', !on);
  $('ms-spin-label').textContent = t(on ? 'map.spin.on' : 'map.spin.off');
}

function setMapStyle(style) {
  for (const [id, st] of Object.entries(MAP_STYLES)) {
    $(id).classList.toggle('on', st === style);
  }
  // вращать имеет смысл только глобус
  $('ms-spin').classList.toggle('hidden', style !== 'globe');
  worldMap.setStyle(style);
  renderMap();
}

function renderMap() {
  const rep = state.report;
  const routes = (rep && rep.routes) || [];
  $('map-empty').classList.toggle('hidden', !!routes.length);

  const geoDirect = rep && rep.geoDirect;
  const geoProxy = rep && rep.geoProxy;
  renderMapSummary(routes, geoProxy);

  // подсказка «гео выключено» — когда включена карта, но не сам geo-lookup
  const glOn = !!(state.cfg && state.cfg.Map && state.cfg.Map.GeoLookup);
  $('map-geo-off').classList.toggle('hidden', glOn);

  if (!worldMap) return;
  const hasCoords = g => !!g && !(g.lat === 0 && g.lon === 0);
  worldMap.setData({
    routes,
    geoDirect: hasCoords(geoDirect) ? geoDirect : null,
    geoProxy: hasCoords(geoProxy) ? geoProxy : null,
    labels: {
      here: t('map.geo.you'), vpn: t('map.geo.vpn'),
      break: t('map.mark.break'), pop: t('map.mark.pop'),
      ok: t('map.mark.ok'), dim: t('map.mark.dim'),
      blocked: t('map.mark.blocked'),
    },
  });
}

function renderAll() {
  updateSubline();
  updateButton();
  renderConfigError();
  renderEnv();
  renderChain();
  renderVerdict();
  renderTable();
  renderHistory();
  updateTabs();
  renderServices();
  renderMap();
}

/* ──────────────── прогон ──────────────── */

// resetRunUI — экран под новый прогон: старые данные уходят целиком, чтобы
// на них нельзя было смотреть как на свежие. Окружение не трогаем — оно
// придёт событием через долю секунды, и мигать прочерками ни к чему.
function resetRunUI() {
  state.report = null;
  state.selectedAt = '';
  state.doneLayers = new Set();
  state.live = [];
  state.liveFor = '';
  state.stick = true;
  state.error = null;
  state.histError = null; // прошлая ошибка истории к новому прогону не относится
  state.canceling = false;
  state.progress = null;
  state.collecting = true;
  // карточка «свой сайт» — ответ про прошлую картину сети, новый прогон её снимает
  state.single = {running: false, host: state.single.host,
    report: null, errKey: null, errText: null, added: false};
  group = {layer: null, tr: null, worst: 'ok'};

  clearTable(t('table.running'));
  updateButton();
  renderChain();
  renderVerdict();   // он же чистит счётчик и метку времени
  renderHistory();   // снимаем подсветку прошлого прогона
  renderMap();       // лучи и сводка прошлого прогона тоже не наши
}

// isBusyStub — пустой Report с нулевым временем: бэкенд уже гоняет прогон
// (наш промис RunCheck потерян перезагрузкой страницы), второй не начат.
// Итог того прогона придёт событием "done".
const isBusyStub = rep =>
  !rep || !rep.startedAt || new Date(rep.startedAt).getTime() <= 0;

// finishRun — единый финал прогона. Зовётся дважды: из промиса RunCheck и
// из события "done" (для фронта, пережившего перезагрузку); кто первый
// успел — тот и закрыл, второй вызов — no-op.
async function finishRun(rep) {
  if (!state.running) return;
  state.running = false;
  state.canceling = false;
  if (rep) {
    state.report = rep;
    if (rep.env) state.env = rep.env;
    state.selectedAt = rep.startedAt || '';
    state.liveFor = rep.startedAt || '';
  }
  try { state.history = await GetHistory() || []; } catch (e) { console.error(e); }
  state.collecting = false; // всё, что могло прийти, пришло
  renderAll();
}

async function run() {
  if (state.running) return;
  state.running = true;
  resetRunUI();

  let rep = null;
  try {
    rep = await RunCheck();
  } catch (e) {
    state.error = (e && e.message) ? e.message : String(e);
    await finishRun(null);
    return;
  }
  if (isBusyStub(rep)) return; // прогон уже шёл — итог придёт событием "done"
  await finishRun(rep);
}

// cancelRun — «Отменить» нажато: кнопка гаснет с «останавливаю…», бэкенд
// рвёт контекст прогона, а итог всё равно приходит обычным путём.
function cancelRun() {
  if (!state.running || state.canceling) return;
  state.canceling = true;
  updateButton();
  CancelCheck().catch(e => console.error(e));
}

/* ──────────────── свой сайт (§3) ──────────────── */

// showSingleErr — ошибка под полем «проверить свой сайт»; null прячет её
function showSingleErr(key) {
  const el = $('single-err');
  el.textContent = key ? t(key) : '';
  el.classList.toggle('hidden', !key);
}

// hostInList — хост уже в «моём списке»: отмечен в справочнике или своя цель
function hostInList(host) {
  const known = catBy(host);
  if (known && state.picked.has(known.id)) return true;
  return state.custom.some(c => c.host === host);
}

function renderSingleCard() {
  const el = $('single-card');
  const sg = state.single;
  let h = '';
  if (sg.running) {
    h = `<div class="scard"><h4>${esc(t('single.title'))}</h4>` +
      `<p class="sdim">${esc(t('single.running'))} ${esc(sg.host)}</p></div>`;
  } else if (sg.errKey) {
    h = `<div class="scard"><h4>${esc(t('single.title'))}</h4>` +
      `<p class="swarn">${esc(t(sg.errKey))}</p></div>`;
  } else if (sg.errText) {
    h = `<div class="scard"><h4>${esc(t('single.title'))}</h4>` +
      `<p class="serr">${esc(t('err.run'))}: ${esc(sg.errText)}</p></div>`;
  } else if (sg.report) {
    const svcs = (sg.report.verdict && sg.report.verdict.services) || [];
    const s = svcs.find(x => x.host === sg.host);
    // строка своего сайта раскрыта сразу — ответ и есть смысл карточки;
    // пробы берутся из её собственного отчёта, а не из общего прогона
    const body = s
      ? svcRowHTML(s, {open: true, add: !hostInList(sg.host) && !sg.added, report: sg.report})
      : `<p class="sdim">${esc(((sg.report.verdict || {}).lines || [])[0] || '—')}</p>`;
    h = `<div class="scard"><h4>${esc(t('single.title'))}</h4>${body}</div>`;
  }
  el.innerHTML = h;
  el.classList.toggle('hidden', !h);
}

// finishSingle — единый финал точечной проверки: зовётся из промиса
// RunSingle и из события single-done; кто первый успел — тот и закрыл.
function finishSingle(rep, errText) {
  if (!state.single.running) return;
  state.single.running = false;
  if (errText) state.single.errText = errText;
  else state.single.report = rep || null;
  renderSingleCard();
  updateButton();
}

async function runSingle() {
  if (state.running || state.single.running) return;
  const raw = $('single-host').value.trim()
    .replace(/^[a-z+.-]+:\/\//i, '').replace(/\/.*$/, '');
  if (!raw) return;
  // та же валидация, что у своих целей: молча глотать опечатку — значит врать
  if (!hostOk(raw)) {
    showSingleErr(/[^\x00-\x7f]/.test(raw) ? 'svc.err.idn' : 'svc.err.host');
    return;
  }
  showSingleErr(null);
  state.single = {running: true, host: raw, report: null, errKey: null, errText: null, added: false};
  renderSingleCard();
  updateButton();
  let rep = null;
  try {
    rep = await RunSingle(raw);
  } catch (e) {
    console.error(e);
    finishSingle(null, (e && e.message) ? e.message : String(e));
    return;
  }
  // Пустой Report с нулевым временем — бэкенд занят другим прогоном:
  // наш single не стартовал, итога не будет (событие run-busy говорит то же).
  if (isBusyStub(rep)) {
    if (state.single.running) {
      state.single.running = false;
      state.single.errKey = 'single.busy';
      renderSingleCard();
      updateButton();
    }
    return;
  }
  finishSingle(rep);
}

// addSingleToList — «добавить в мой список»: тот же механизм, что у своих
// целей на вкладке «Сервисы» (известный хост — галочка, новый — custom).
async function addSingleToList() {
  const raw = state.single.host;
  if (!raw) return;
  const known = catBy(raw);
  if (known) state.picked.add(known.id);
  else if (!state.custom.some(c => c.host === raw)) state.custom.push({host: raw, group: 'blocked'});
  state.single.added = true;
  await persistAndRender(); // сохраняет выбор; при ошибке откатит его к конфигу
  renderSingleCard();       // кнопка «добавить» исчезает
}

/* ──────────────── настройки ──────────────── */

// Шрифты приходят с бэкенда готовым CSS (переменные --hudfont/--mono плюс
// @font-face, если выбран файл с диска).
async function applyFontCSS() {
  try {
    const css = await FontCSS();
    let el = $('font-css');
    if (!el) {
      el = document.createElement('style');
      el.id = 'font-css';
      document.head.appendChild(el);
    }
    el.textContent = css || '';
  } catch (e) { console.error(e); }
  // окно должно вместить увеличенную вёрстку — минимальный размер считает бэкенд
  try { await ApplyWindowScale(); } catch (e) { console.error(e); }
}

function fillFontSelect(sel, families, current) {
  const opts = [`<option value="">${esc(t('set.font_default'))}</option>`];
  for (const f of families) {
    opts.push(`<option value="${esc(f)}">${esc(f)}</option>`);
  }
  // шрифт из конфига может быть не установлен — сохраняем его в списке
  if (current && !families.includes(current)) {
    opts.push(`<option value="${esc(current)}">${esc(current)}</option>`);
  }
  sel.innerHTML = opts.join('');
  sel.value = current || '';
}

async function openSettings() {
  if (!state.fonts) {
    try { state.fonts = await ListFonts() || []; } catch (e) { state.fonts = []; }
  }
  const ui = (state.cfg && state.cfg.UI) || {};
  $('set-lang').value = getLang();
  $('set-scale').value = ui.Scale || 'm';
  fillFontSelect($('set-font-hud'), state.fonts, ui.FontHUD || '');
  fillFontSelect($('set-font-mono'), state.fonts, ui.FontMono || '');
  $('set-font-file').value = ui.FontFile || '';
  const map = (state.cfg && state.cfg.Map) || {};
  $('set-map-on').checked = map.Enabled !== false;
  $('set-geo').checked = !!map.GeoLookup;
  $('settings').classList.remove('hidden');
}

function closeSettings() { $('settings').classList.add('hidden'); }

async function saveSettings() {
  // Конфиг мог не прочитаться при старте. Молча закрыть окно, выбросив всё,
  // что человек только что выставил, — худшее из возможного: бэкенд примет
  // и неполный конфиг, дополнив его умолчаниями.
  const cfg = state.cfg || {};
  cfg.UI = Object.assign({}, cfg.UI, {
    Scale: $('set-scale').value,
    FontHUD: $('set-font-hud').value,
    FontMono: $('set-font-mono').value,
    FontFile: $('set-font-file').value.trim(),
  });
  cfg.Map = Object.assign({}, cfg.Map, {
    Enabled: $('set-map-on').checked,
    GeoLookup: $('set-geo').checked,
  });
  try {
    await SaveConfig(cfg);
    state.cfg = await GetConfig();
  } catch (e) { console.error(e); }
  await applyFontCSS();
  await switchLang($('set-lang').value);
  renderAll(); // вкладка и подсказки карты зависят от cfg.Map
  closeSettings();
}

/* ──────────────── прошлые прогоны ──────────────── */

// Отчёты хранятся целиком, поэтому прошлый прогон открывается как свежий:
// бэкенд отдаёт его с вердиктом на текущем языке.
async function loadRun(at) {
  // Открывать прошлый прогон посреди текущего нельзя: живые строки уже
  // в таблице, и подмена отчёта под ними сделала бы её наполовину чужой.
  if (state.running) return false;
  try {
    const rep = await GetRun(at || '');
    if (!rep) return false;
    state.report = rep;
    if (rep.env) state.env = rep.env;
    state.selectedAt = rep.startedAt || at || '';
    // прогон из истории — свои живые строки к нему не относятся
    if (!sameRun(state.liveFor, rep.startedAt)) { state.live = []; state.liveFor = ''; }
    renderAll();
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
}

/* ──────────────── язык ──────────────── */

async function switchLang(l) {
  if (l === getLang()) return;
  // applyLang перепишет подписи по data-i18n, в том числе на взведённой
  // кнопке очистки: она снова станет выглядеть как «Очистить», оставаясь
  // взведённой, и следующий клик стёр бы историю без вопроса.
  if (clearArmed) armClear(false);
  applyLang(l);
  try { await SetLang(l); } catch (e) { console.error(e); }
  // вердикт и итоги истории пересобираются бэкендом на новом языке
  try { state.history = await GetHistory() || []; } catch (e) { console.error(e); }
  // справочник сервисов бэкенд отдаёт уже переведённым — перечитываем
  try { await loadCatalog(); } catch (e) { console.error(e); }
  if (state.report) await loadRun(state.selectedAt);
  renderAll();
}

/* ──────────────── старт ──────────────── */

async function init() {
  EventsOn('env', snap => { state.env = snap; renderEnv(); });
  // конфиг не прочитался — прогон идёт с дефолтами, об этом сказано тихо
  EventsOn('config-error', msg => {
    state.configError = String(msg || 'config');
    renderConfigError();
  });
  // Финал прогона, промис которого потерян перезагрузкой страницы:
  // без этого события такой фронт не дожил бы до отчёта.
  EventsOn('done', rep => { finishRun(rep); });
  // тот же механизм для точечной проверки (итог приходит НЕ событием done)
  EventsOn('single-done', rep => { finishSingle(rep); });
  // бэкенд занят другим прогоном — точечная проверка не стартовала
  EventsOn('run-busy', () => {
    if (!state.single.running) return;
    state.single.running = false;
    state.single.errKey = 'single.busy';
    renderSingleCard();
    updateButton();
  });
  EventsOn('progress', p => {
    if (!p || !p.layer) return;
    // тик счётчика целей — только цифры на кнопке, в таблицу ему нечего
    if (p.total) {
      state.progress = {done: p.checked || 0, total: p.total};
      if (state.running) $('btn-sub').textContent = progressText();
    }
    if (p.result) {
      // Очередная проба ответила — строка уходит в таблицу немедленно.
      // Признак «собираем» держится дольше, чем «идёт прогон»: последние
      // события успевают прийти уже после того, как RunCheck вернул отчёт,
      // и выбрасывать их значило бы расходиться с отчётом на пару строк.
      if (!state.collecting) return;
      state.live.push({layer: p.layer, r: p.result});
      appendRow(p.layer, p.result);
      tableMeta(state.live.length, new Set(state.live.map(x => x.layer)).size);
      stickBottom();
      return;
    }
    if (p.done) { state.doneLayers.add(p.layer); if (state.running) renderChain(); }
  });

  let lang = 'ru';
  try { lang = await CurrentLang(); } catch (e) { console.error(e); }
  applyLang(lang);

  try { state.version = await Version(); } catch (e) { console.error(e); }
  try { state.cfg = await GetConfig(); } catch (e) { console.error(e); }
  try { state.history = await GetHistory() || []; } catch (e) { console.error(e); }

  try { await loadCatalog(); } catch (e) { console.error(e); }

  await applyFontCSS();
  initMap();
  const saved = state.cfg && state.cfg.UI && state.cfg.UI.Tab;
  setTab(TABS.includes(saved) ? saved : 'report');
  renderAll();

  // последний прогон переживает перезапуск — показываем его сразу
  await loadRun('');

  // во время прогона та же кнопка — «Отменить»
  $('btn-run').addEventListener('click', () => {
    if (state.running) cancelRun();
    else run();
  });

  // точечная проверка своего сайта
  $('single-btn').addEventListener('click', runSingle);
  $('single-host').addEventListener('keydown', e => {
    if (e.key === 'Enter') runSingle();
  });
  // человек начал править адрес — старая ошибка больше не про этот ввод
  $('single-host').addEventListener('input', () => showSingleErr(null));

  // выдача по сервисам: раскрытие строк, замер скорости, «добавить в список».
  // Один делегированный слушатель на контейнер — строки пересобираются целиком.
  for (const cid of ['svclist', 'single-card']) {
    $(cid).addEventListener('click', e => {
      const mb = e.target.closest('.smeasure');
      if (mb) { measureSpeed(mb.dataset.id); return; }
      if (e.target.closest('.sadd')) { addSingleToList().catch(err => console.error(err)); return; }
      const hd = e.target.closest('.shead');
      if (hd) toggleSvcRow(hd.closest('.srow'));
    });
  }

  // раскрывашка «Технические детали»: состояние живёт в сессии,
  // в конфиг сознательно не пишется (упрощение против спеки — так решено)
  let techOpen = false;
  $('tech-hd').addEventListener('click', () => {
    techOpen = !techOpen;
    $('tech-pan').classList.toggle('collapsed', !techOpen);
    $('tech-pan').querySelector('.tcaret').textContent = techOpen ? '▴' : '▾';
    // пока раскрывашка была закрыта, прокрутка таблицы стояла в нуле
    if (techOpen) requestAnimationFrame(stickBottom);
  });

  // автопрокрутка живой таблицы держится, пока человек не отлистал вверх
  const tbd = $('tbody').closest('.bd');
  if (tbd) {
    tbd.addEventListener('scroll', () => {
      state.stick = tbd.scrollHeight - tbd.scrollTop - tbd.clientHeight < 24;
    });
  }

  $('hist-clear').addEventListener('click', () => {
    if (state.running || !(state.history || []).length) return;
    if (!clearArmed) { armClear(true); return; }
    if (Date.now() - armedAt < armCooldown) return; // защита от двойного клика
    armClear(false);
    queueHist(() => removeRuns(null));
  });
  $('hist-clear').addEventListener('blur', () => { if (clearArmed) armClear(false); });

  for (const name of TABS) $('tab-' + name).addEventListener('click', () => setTab(name));

  $('svc-presets').addEventListener('click', e => {
    const b = e.target.closest('button[data-preset]');
    if (b) applyPreset(b.dataset.preset);
  });
  $('svc-search').addEventListener('input', e => {
    state.svcQuery = e.target.value;
    renderServices();
  });
  $('svc-add').addEventListener('click', addCustomTarget);
  $('svc-host').addEventListener('keydown', e => {
    if (e.key === 'Enter') addCustomTarget();
  });
  // человек начал править адрес — старая ошибка больше не про этот ввод
  $('svc-host').addEventListener('input', () => showSvcErr(null));

  $('gear').addEventListener('click', openSettings);
  $('set-cancel').addEventListener('click', closeSettings);
  $('set-save').addEventListener('click', saveSettings);
  $('settings').addEventListener('click', e => {
    if (e.target === $('settings')) closeSettings(); // клик по затемнению
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !$('settings').classList.contains('hidden')) closeSettings();
  });
}

init();
