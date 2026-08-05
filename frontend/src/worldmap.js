// Карта мира на настоящей географии Natural Earth (public domain, 110m).
//
// Три стиля на выбор:
//   globe     — ортографическая проекция, вращающийся «глобус» (крутится мышью)
//   countries — страны с границами, равнопромежуточная цилиндрическая
//   dots      — точечная матрица: суша выложена точками, самый HUD-овый вид
//
// География рисуется на <canvas> (нужна плавность вращения), а якоря и метки —
// DOM-слоем поверх: так у них остаются подсказки и нормальный текст.

import {geoOrthographic, geoEquirectangular, geoPath, geoGraticule10,
  geoCentroid, geoInterpolate, geoBounds} from 'd3-geo';
import {feature} from 'topojson-client';
import landTopo from './data/land-110m.json';
import countriesTopo from './data/countries-110m.json';
import isoNumeric from './data/iso-numeric.json';

const LAND = feature(landTopo, landTopo.objects.land);
const COUNTRIES = feature(countriesTopo, countriesTopo.objects.countries);
const GRATICULE = geoGraticule10();

// Бэкенд знает страну шага как код ISO alpha-2, а контуры Natural Earth
// размечены числовым кодом ISO. Связываем одно с другим и заодно считаем
// центр каждой страны: точнее страны по бесплатным базам всё равно не узнать,
// и притворяться, что знаем город, было бы враньём.
const BY_CODE = (() => {
  const byId = new Map(COUNTRIES.features.map(f => [String(f.id), f]));
  const out = new Map();
  for (const [alpha2, numeric] of Object.entries(isoNumeric)) {
    const f = byId.get(String(numeric));
    if (!f) continue;
    // radiusKm — насколько далеко от центра страны может лежать её роутер.
    // Для Нидерландов это полторы сотни километров, для России — тысячи,
    // и без этой поправки любая проверка расстояния от центроида врала бы
    // ровно на размер страны.
    const [[w, s], [e, n]] = geoBounds(f);
    const half = angularDistance([w, s], [e, n]) * Math.PI / 180 * 6371 / 2;
    out.set(alpha2, {feature: f, at: geoCentroid(f), radiusKm: half});
  }
  return out;
})();

const placeOf = code => (code && BY_CODE.get(code)) || null;

const EARTH_KM = 6371;
const kmBetween = (a, b) => angularDistance(a, b) * Math.PI / 180 * EARTH_KM;

// reachableKm — насколько далеко физически может стоять машина, ответившая
// за rtt мс. Тот же расчёт, что в geo.ReachableKm на бэкенде: свет в волокне
// идёт около 200 км/мс, ответ проходит путь дважды.
const reachableKm = rtt => (rtt > 0 ? rtt / 2 * 200 : 0);

// waypoints — во что превращается маршрут на карте.
//
// Точка шага берётся из трёх источников по убыванию достоверности:
//
//   1. Координаты города из имени роутера (n.at) — их ставит бэкенд, разобрав
//      обратную DNS-запись. Это единственный источник, который знает, где
//      железо стоит физически.
//   2. Центроид страны из геобазы — грубо, но лучше, чем ничего.
//   3. Ничего: шаг не рисуется.
//
// Шаги, для которых бэкенд доказал невозможность (n.implausible), выброшены
// им же. Здесь остаётся проверить лишь те, что размещены по стране: центроид
// отстоит от настоящего роутера на полстраны, поэтому к бюджету добавляется
// радиус страны — иначе Германия с 35 мс отбраковывалась бы у пользователя
// в Москве только потому, что центроид России лежит в Сибири.
function waypoints(route) {
  const out = [];
  const end = route.break;
  const anchor = route.anchor ? [route.anchor.lon, route.anchor.lat] : null;

  for (const n of route.nodes || []) {
    if (n.private || n.implausible) continue;
    // Ответ пришёл слишком быстро, чтобы «далёкая» страна была правдой:
    // отвечает ближайшая точка присутствия, а не сервер там, где адрес
    // числится. Ставить отметку в той стране нельзя.
    if (route.farCountry && end && n.n === end.n) continue;

    let at = null, code = n.country, feature = null, exact = false;
    if (n.at) {
      at = [n.at.lon, n.at.lat];
      exact = true;
      code = n.city || n.country;
    } else if (n.country) {
      const pl = placeOf(n.country);
      if (!pl) continue;
      at = pl.at;
      feature = pl.feature;
      if (anchor && n.rttMs > 0 &&
          kmBetween(anchor, at) - pl.radiusKm > reachableKm(n.rttMs)) continue;
    }
    if (!at) continue;
    if (!feature && n.country) feature = (placeOf(n.country) || {}).feature || null;

    const prev = out[out.length - 1];
    // Соседние шаги в одном месте — одна точка. Десять роутеров одного
    // Франкфурта не десять отметок, а один Франкфурт.
    if (prev && (prev.code === code || kmBetween(prev.at, at) < 120)) {
      prev.node = n;
      continue;
    }
    // Возврат туда, где уже были, схлопывается только для грубых, страновых
    // точек: «Германия → Британия → Германия» у Telia — это ошибка базы,
    // а не крюк. Для точек, установленных по имени роутера, возврат может
    // быть настоящим, и выбрасывать его нельзя.
    if (!exact) {
      const seen = out.findIndex(w => !w.exact && w.code === code);
      if (seen >= 0) { out.length = seen + 1; out[seen].node = n; continue; }
    }
    out.push({code, at, feature, node: n, exact});
  }
  return out;
}

// arcPoints — точки большого круга между двумя местами. Прямая на плоской
// карте и прямая на глобусе — разные линии; рисуем настоящую.
function arcPoints(proj, from, to, steps = 48) {
  const mid = geoInterpolate(from, to);
  const runs = [];
  let run = [];
  for (let i = 0; i <= steps; i++) {
    const p = proj(steps ? mid(i / steps) : from);
    // На глобусе проекция отсекает обратную сторону — там линия рвётся,
    // и склеивать её через край шара нельзя.
    if (!p || !isFinite(p[0]) || !isFinite(p[1])) {
      if (run.length > 1) runs.push(run);
      run = [];
      continue;
    }
    run.push(p);
  }
  if (run.length > 1) runs.push(run);
  return runs;
}

let DOTS = null; // считается лениво при первом показе точечного стиля

// Узлы сетки, попавшие на сушу. geoContains по каждому узлу слишком дорог,
// поэтому растеризуем сушу в маску и спрашиваем её.
function buildDots(step) {
  const MW = 720, MH = 360;
  const off = document.createElement('canvas');
  off.width = MW; off.height = MH;
  const ctx = off.getContext('2d', {willReadFrequently: true});
  const proj = geoEquirectangular().fitSize([MW, MH], {type: 'Sphere'});
  const path = geoPath(proj, ctx);
  ctx.fillStyle = '#fff';
  ctx.beginPath();
  path(LAND);
  ctx.fill();
  const mask = ctx.getImageData(0, 0, MW, MH).data;

  const pts = [];
  for (let lat = 83; lat >= -58; lat -= step) {
    for (let lon = -180; lon <= 180; lon += step) {
      const p = proj([lon, lat]);
      const x = Math.round(p[0]), y = Math.round(p[1]);
      if (x < 0 || y < 0 || x >= MW || y >= MH) continue;
      if (mask[(y * MW + x) * 4] > 128) pts.push([lon, lat]);
    }
  }
  return pts;
}

const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

export class WorldMap {
  /**
   * @param {HTMLCanvasElement} canvas холст для географии
   * @param {HTMLElement} overlay слой для якорей и меток
   */
  constructor(canvas, overlay) {
    this.canvas = canvas;
    this.overlay = overlay;
    this.style = 'globe';
    this.data = {routes: []};
    this.rotation = [-20, -20]; // стартуем с видом на Европу
    this.autoSpin = true;       // пожелание пользователя, а не текущее состояние
    this.zoom = 1;              // приближение колесом, общее для всех видов
    this.offset = [0, 0];       // сдвиг при перетаскивании плоской карты
    this.drag = null;
    this.raf = null;
    this.onSpinChange = null;

    // Глобус можно взять и покрутить в любую сторону.
    canvas.addEventListener('pointerdown', e => {
      this.drag = {x: e.clientX, y: e.clientY, rot: [...this.rotation], off: [...this.offset]};
      try { canvas.setPointerCapture(e.pointerId); } catch (_) {}
    });
    canvas.addEventListener('pointermove', e => {
      if (!this.drag) return;
      const dx = e.clientX - this.drag.x, dy = e.clientY - this.drag.y;
      if (this.style === 'globe') {
        // глобус крутим в любую сторону; за полюс не переваливаем,
        // иначе картинка встаёт вверх ногами
        const k = 0.35 / this.zoom;
        this.rotation = [
          this.drag.rot[0] + dx * k,
          Math.max(-85, Math.min(85, this.drag.rot[1] - dy * k)),
        ];
      } else {
        // плоскую карту таскаем
        this.offset = [this.drag.off[0] + dx, this.drag.off[1] + dy];
      }
      this.render();
    });
    const stop = () => { this.drag = null; };
    canvas.addEventListener('pointerup', stop);
    canvas.addEventListener('pointercancel', stop);
    canvas.addEventListener('pointerleave', stop);

    // Колесо приближает и отдаляет — на любом виде карты.
    canvas.addEventListener('wheel', e => {
      e.preventDefault();
      const k = Math.exp(-e.deltaY * 0.0015);
      this.zoom = Math.max(1, Math.min(12, this.zoom * k));
      if (this.zoom === 1) this.offset = [0, 0]; // вернулись к исходному виду
      this.render();
    }, {passive: false});

    // Карта должна подстраиваться под окно: при ресайзе перерисовываем.
    if (window.ResizeObserver) {
      this.ro = new ResizeObserver(() => this.render());
      this.ro.observe(canvas.parentElement || canvas);
    }
    window.addEventListener('resize', () => this.render());
  }

  setStyle(style) {
    this.style = style;
    if (style === 'dots' && !DOTS) DOTS = buildDots(2.4);
    this.render();
    this.loop();
  }

  // Авто-вращение включается и выключается пользователем; ручное кручение
  // мышью и колесом работает в любом случае.
  setSpin(on) {
    this.autoSpin = !!on;
    if (this.onSpinChange) this.onSpinChange(this.autoSpin);
  }

  setData(data) {
    this.data = data || {routes: []};
    this.render();
  }

  loop() {
    cancelAnimationFrame(this.raf);
    const tick = () => {
      if (this.style === 'globe' && this.autoSpin && !this.drag) {
        this.rotation[0] += 0.12;
        this.render();
      }
      this.raf = requestAnimationFrame(tick);
    };
    this.raf = requestAnimationFrame(tick);
  }

  destroy() { cancelAnimationFrame(this.raf); }

  projection(w, h) {
    // fitExtent вместо ручного масштаба: глобус гарантированно вписывается
    // в фактический размер холста, каким бы он ни оказался
    const pad = 10;
    const ext = [[pad, pad], [w - pad, h - pad]];
    const p = this.style === 'globe'
      ? geoOrthographic().rotate(this.rotation).clipAngle(90).fitExtent(ext, {type: 'Sphere'})
      : geoEquirectangular().fitExtent(ext, {type: 'Sphere'});

    if (this.zoom === 1 && this.offset[0] === 0 && this.offset[1] === 0) return p;

    // Карту нельзя утащить за край: сдвиг ограничен так, чтобы её края
    // не заезжали внутрь холста. Если после зума карта уже холста —
    // сдвиг вообще запрещён, она стоит по границам.
    const b = geoPath(p).bounds({type: 'Sphere'});
    const mapW = (b[1][0] - b[0][0]) * this.zoom;
    const mapH = (b[1][1] - b[0][1]) * this.zoom;
    const limX = Math.max(0, (mapW - w) / 2);
    const limY = Math.max(0, (mapH - h) / 2);
    this.offset = [
      Math.max(-limX, Math.min(limX, this.offset[0])),
      Math.max(-limY, Math.min(limY, this.offset[1])),
    ];

    // Приближаем относительно центра холста и учитываем перетаскивание.
    const s = p.scale(), t = p.translate();
    const cx = w / 2, cy = h / 2;
    return p.scale(s * this.zoom).translate([
      cx + (t[0] - cx) * this.zoom + this.offset[0],
      cy + (t[1] - cy) * this.zoom + this.offset[1],
    ]);
  }

  render() {
    const canvas = this.canvas;
    // Размер берём у контейнера и именно clientWidth/clientHeight:
    // при масштабе интерфейса (body{zoom}) getBoundingClientRect отдаёт уже
    // умноженные на масштаб числа, а ширина холста задаётся в обычных
    // пикселях — из-за этого карта вылезала за края и уводила управление.
    const box = canvas.parentElement || canvas;
    const rect = {width: box.clientWidth, height: box.clientHeight};
    if (!rect.width || !rect.height) return;

    // Экранный размер задаём явно в px: при масштабе интерфейса (body{zoom})
    // проценты и devicePixelRatio расходятся, и карта уезжала за края.
    const dpr = window.devicePixelRatio || 1;
    const w = Math.round(rect.width), h = Math.round(rect.height);
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
    }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const proj = this.projection(w, h);
    const path = geoPath(proj, ctx);

    const hud = css('--hud') || '#5fd9f5';
    const hudDim = css('--hud-dim') || '#2b6a80';
    const line2 = css('--line-2') || '#243447';
    const surface = css('--surface') || '#0b1119';

    if (this.style === 'globe') {
      ctx.beginPath(); path({type: 'Sphere'});
      ctx.fillStyle = 'rgba(95,217,245,.05)'; ctx.fill();

      ctx.beginPath(); path(GRATICULE);
      ctx.strokeStyle = 'rgba(95,217,245,.13)'; ctx.lineWidth = 0.6; ctx.stroke();

      ctx.beginPath(); path(LAND);
      ctx.fillStyle = surface; ctx.fill();
      ctx.strokeStyle = hudDim; ctx.lineWidth = 0.9; ctx.stroke();

      ctx.beginPath(); path({type: 'Sphere'});
      ctx.strokeStyle = hud; ctx.lineWidth = 1.1; ctx.stroke();
    } else if (this.style === 'countries') {
      ctx.beginPath(); path(GRATICULE);
      ctx.strokeStyle = 'rgba(95,217,245,.07)'; ctx.lineWidth = 0.6; ctx.stroke();

      ctx.beginPath(); path(COUNTRIES);
      ctx.fillStyle = surface; ctx.fill();
      ctx.strokeStyle = line2; ctx.lineWidth = 0.7; ctx.stroke();
    } else {
      if (!DOTS) DOTS = buildDots(2.4);
      ctx.fillStyle = hudDim;
      for (const [lon, lat] of DOTS) {
        const p = proj([lon, lat]);
        if (!p) continue;
        ctx.beginPath();
        ctx.arc(p[0], p[1], 1.1, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    this.drawRoutes(ctx, proj, path);
    this.renderOverlay(proj, w, h);
  }

  // Лучи от пользователя до места, где путь кончился. Красится участок
  // маршрута, а не страна назначения: у сервиса за CDN страны попросту нет,
  // а вот докуда дошли пакеты — измеримо.
  drawRoutes(ctx, proj, path) {
    const routes = this.data.routes || [];
    if (!routes.length) return;

    const ok = css('--good') || '#3ad684';
    const bad = css('--crit') || '#ff4d5e';

    // Страна, в которой оборвался путь, подсвечивается заливкой — но только
    // на видах со странами: на точечном виде подсвечивать нечего.
    if (this.style !== 'dots') {
      const broken = new Set();
      for (const r of routes) {
        // Живой сервис с недошедшей трассировкой — не обрыв, а фильтрация
        // ICMP по пути. Красить за это страну значило бы обвинять её зря.
        if (r.reached || r.opaque) continue;
        const wps = waypoints(r);
        const last = wps[wps.length - 1];
        if (last) broken.add(last.feature);
      }
      for (const f of broken) {
        ctx.beginPath();
        path(f);
        ctx.fillStyle = 'rgba(255,93,93,.14)';
        ctx.fill();
      }
    }

    for (const r of routes) {
      const wps = waypoints(r);
      if (wps.length < 2) continue;
      ctx.lineWidth = 1.4;
      ctx.lineCap = 'round';
      for (let i = 1; i < wps.length; i++) {
        // Пунктиром — только последний участок оборвавшегося маршрута:
        // до него путь проходил нормально, и это видно.
        // Пунктиром отмечается последний участок и у оборвавшегося маршрута,
        // и у дошедшего до заблокированного сервиса: в обоих случаях дальше
        // этой точки ничего не работает, хотя причины разные.
        const dashed = (!r.reached || r.serviceOK === false) && i === wps.length - 1;
        ctx.setLineDash(dashed ? [4, 4] : []);
        // Пунктир обрыва красный, пунктир непрослеживаемого маршрута —
        // нейтральный: там ничего не сломано, просто не видно.
        ctx.strokeStyle = !dashed || r.opaque ? ok : bad;
        ctx.globalAlpha = r.opaque ? 0.35 : r.reached ? 0.5 : 0.75;
        for (const run of arcPoints(proj, wps[i - 1].at, wps[i].at)) {
          ctx.beginPath();
          ctx.moveTo(run[0][0], run[0][1]);
          for (let k = 1; k < run.length; k++) ctx.lineTo(run[k][0], run[k][1]);
          ctx.stroke();
        }
      }
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
    }
  }

  // Якоря и метки — DOM поверх холста: нужны подсказки и читаемый текст.
  renderOverlay(proj, w, h) {
    const ov = this.overlay;
    ov.innerHTML = '';
    ov.style.width = w + 'px';
    ov.style.height = h + 'px';

    // на глобусе точки обратной стороны прятать обязательно, иначе Сидней
    // окажется поверх Атлантики
    const center = [-this.rotation[0], -this.rotation[1]];
    const visible = (lon, lat) =>
      this.style !== 'globe' || angularDistance(center, [lon, lat]) < 89;

    const put = (el, x, y) => {
      el.style.left = x + 'px';
      el.style.top = y + 'px';
      ov.appendChild(el);
    };

    // Концы лучей группируются по стране и исходу: до одной и той же точки
    // обрыва приходит десяток сервисов, и десять отметок друг на друге
    // не сказали бы ничего сверх одной с числом.
    const labels = this.data.labels || {};
    const ends = new Map();
    for (const r of this.data.routes || []) {
      const wps = waypoints(r);
      const last = wps[wps.length - 1];
      if (!last) continue;
      // Порядок важен: «пакеты дошли, а сервис не работает» — это блокировка,
      // и назвать её «маршрут дошёл» значило бы противоречить отчёту,
      // где тот же сервис помечен недоступным.
      const kind = r.opaque ? 'dim'
        : !r.reached ? 'break'
        : r.serviceOK === false ? 'blocked'
        : r.farCountry ? 'pop' : 'ok';
      const key = last.code + '|' + kind;
      let g = ends.get(key);
      if (!g) {
        g = {at: last.at, code: last.code, kind, node: last.node, hosts: [], notes: new Set()};
        ends.set(key, g);
      }
      g.hosts.push(r.host);
      if (r.note) g.notes.add(r.note);
    }

    // К одной и той же стране приходят и оборвавшиеся маршруты, и дошедшие.
    // Подписи у них ложатся в одну точку и перекрывают друг друга, поэтому
    // каждую следующую сдвигаем вниз, пока место не освободится.
    const taken = [];
    const freeSpot = (x, y) => {
      let shift = 0;
      while (taken.some(t => Math.abs(t.x - x) < 120 && Math.abs(t.y - (y + shift)) < 12)) {
        shift += 13;
        if (shift > 130) break; // не уводить подпись за пределы разумного
      }
      taken.push({x, y: y + shift});
      return y + shift;
    };

    for (const g of ends.values()) {
      if (!visible(g.at[0], g.at[1])) continue;
      const p = proj(g.at);
      if (!p || !isFinite(p[0])) continue;

      const owner = g.node && g.node.org
        ? `AS${g.node.asn} ${g.node.org}`
        : (g.node && g.node.ip) || g.code;

      const mark = document.createElement('div');
      mark.className = g.kind === 'break' ? 'mx'
        : g.kind === 'pop' ? 'mpop'
        : g.kind === 'dim' ? 'mdim'
        : g.kind === 'blocked' ? 'mdot bad'
        : 'mdot ok';
      mark.title = [
        `${labels[g.kind] || g.kind}: ${owner}`,
        g.hosts.join(', '),
        ...g.notes,
      ].filter(Boolean).join('\n');
      put(mark, p[0], p[1]);

      // у правого края подпись уходит влево, иначе её срезает границей окна
      const left = p[0] > w * 0.78;
      const lab = document.createElement('div');
      lab.className = 'mlab' + (left ? ' left' : '') + (g.kind === 'break' ? ' bad' : '');
      lab.textContent = g.hosts.length > 1 ? `${owner} · ${g.hosts.length}` : owner;
      put(lab, p[0] + (left ? -9 : 9), freeSpot(p[0], p[1] - 7));
    }

    const pin = (info, cls, label) => {
      if (!info || (!info.lat && !info.lon)) return null;
      if (!visible(info.lon, info.lat)) return null;
      const p = proj([info.lon, info.lat]);
      if (!p || !isFinite(p[0])) return null;
      const el = document.createElement('div');
      el.className = 'mpin ' + cls;
      el.title = `${label}: ${info.city || ''} ${info.country || ''} ${info.ip || ''}`.trim();
      put(el, p[0], p[1]);
      const lab = document.createElement('div');
      lab.className = 'mlab pin';
      lab.textContent = `${label}: ${info.city || info.country || info.ip || ''}`;
      // Метки «ты здесь» и «выход VPN» разводятся тем же механизмом,
      // что и подписи лучей: они ложатся в те же места на карте.
      put(lab, p[0] + 10, freeSpot(p[0] + 10, p[1] + 9));
      return p;
    };

    const a = pin(this.data.geoDirect, 'here', labels.here || 'you');
    const b = pin(this.data.geoProxy, 'vpn', labels.vpn || 'VPN');
    if (a && b) {
      const line = document.createElement('div');
      line.className = 'mline';
      const dx = b[0] - a[0], dy = b[1] - a[1];
      line.style.left = a[0] + 'px';
      line.style.top = a[1] + 'px';
      line.style.width = Math.hypot(dx, dy) + 'px';
      line.style.transform = `rotate(${Math.atan2(dy, dx)}rad)`;
      ov.appendChild(line);
    }
  }
}

// угловое расстояние между точками на сфере, в градусах
function angularDistance(a, b) {
  const toRad = d => d * Math.PI / 180;
  const lon1 = toRad(a[0]), lat1 = toRad(a[1]);
  const lon2 = toRad(b[0]), lat2 = toRad(b[1]);
  const c = Math.sin(lat1) * Math.sin(lat2) +
    Math.cos(lat1) * Math.cos(lat2) * Math.cos(lon2 - lon1);
  return Math.acos(Math.max(-1, Math.min(1, c))) * 180 / Math.PI;
}
