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
  geoInterpolate} from 'd3-geo';
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
    out.set(alpha2, f);
  }
  return out;
})();

// Контур страны нужен ровно для одного: подсветить заливкой ту, в которой
// оборвался путь. Центр страны не нужен вовсе — точки шагов ставит бэкенд
// по имени роутера или по узлу связи, а центроид России лежит в Сибири.
const placeOf = code => {
  const f = code && BY_CODE.get(code);
  return f ? {feature: f} : null;
};

// SEVERITY — исходы от безобидного к худшему. Когда в одну точку приходят
// разные маршруты, значок берётся по худшему из них: «сюда доходит» рядом
// с «здесь обрывается» — это не два равноправных факта, а один повод
// посмотреть внимательнее.
const SEVERITY = ['ok', 'dim', 'pop', 'blocked', 'break'];

const EARTH_KM = 6371;
const kmBetween = (a, b) => angularDistance(a, b) * Math.PI / 180 * EARTH_KM;

// waypoints — во что превращается маршрут на карте.
//
// Рисуются только места, которые можно назвать: город из имени роутера
// или узел связи страны, переживший проверку временем. Оба ставит бэкенд.
// Центроида страны здесь больше нет, и это принципиально: у России он
// в Сибири, у США — в Монтане, и шаг, размещённый туда, был бы не «грубо,
// но лучше, чем ничего», а уверенным враньём на четыре тысячи километров.
// Шаг, который разместить нечем, точки не даёт — луч просто идёт мимо него.
//
// Шаги, у которых бэкенд доказал невозможность (n.implausible) или поймал
// развилку пути (n.ambiguous — на повторный вопрос ответил другой роутер),
// выброшены им же: одной точкой они не описываются.
function waypoints(route) {
  const out = [];
  const end = route.break;

  // Луч начинается там, где сидит пользователь. Это единственная точка,
  // которую мы знаем точно, и без неё маршрут, у которого первые шаги
  // разместить не удалось, начинался бы из ниоткуда — а чаще не рисовался
  // вовсе: собственный роутер провайдера в четырёх миллисекундах от нас
  // размещению не поддаётся, и без этой точки половина лучей исчезала.
  if (route.anchor) {
    out.push({code: ' you', at: [route.anchor.lon, route.anchor.lat],
      feature: null, node: null, exact: true});
  }

  for (const n of route.nodes || []) {
    if (n.private || n.implausible || n.ambiguous || !n.at) continue;
    // Ответ пришёл слишком быстро, чтобы «далёкая» страна была правдой:
    // отвечает ближайшая точка присутствия, а не сервер там, где адрес
    // числится. Ставить отметку в той стране нельзя.
    if (route.farCountry && end && n.n === end.n) continue;

    const at = [n.at.lon, n.at.lat];
    // exact — точка из имени роутера. Точка по стране (n.guessed) остаётся
    // догадкой, и правило «возврат в ту же страну — ошибка базы, а не крюк»
    // должно работать для неё, как работало до появления узлов связи.
    const exact = !n.guessed;
    const code = n.city || n.country;
    const feature = (placeOf(n.country) || {}).feature || null;

    const prev = out[out.length - 1];
    // Соседние шаги в одном месте — одна точка. Десять роутеров одного
    // Франкфурта не десять отметок, а один Франкфурт.
    if (prev && (prev.code === code || kmBetween(prev.at, at) < 120)) {
      prev.node = n;
      // Точка «ты здесь» приходит без страны — она поглощает первый шаг,
      // и контур страны надо забрать у него, иначе обрыв нечем подсветить.
      if (!prev.feature) prev.feature = feature;
      if (prev.code === ' you') prev.code = code;
      continue;
    }
    // Возврат туда, где уже были, схлопывается только для грубых, страновых
    // точек: «Германия → Британия → Германия» у Telia — это ошибка базы,
    // а не крюк. Для точек, установленных по имени роутера, возврат может
    // быть настоящим, и выбрасывать его нельзя. Срезать хвост можно тоже
    // только без exact-точек в нём: между двумя вхождениями страны мог
    // лежать настоящий город из имени роутера, и жертвовать знанием ради
    // починки догадки нельзя — тогда это настоящий крюк, а не ошибка базы.
    if (!exact) {
      const seen = out.findIndex(w => !w.exact && w.code === code);
      if (seen >= 0 && !out.slice(seen + 1).some(w => w.exact)) {
        out.length = seen + 1; out[seen].node = n; continue;
      }
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
  let prevLon = null;
  for (let i = 0; i <= steps; i++) {
    const ll = steps ? mid(i / steps) : from;
    // Кратчайшая дуга из России в США идёт через полюс и пересекает 180-й
    // меридиан. На плоской карте долгота там прыгает с +179 на -179, и линия
    // рисовалась полосой через весь экран — от Аляски до Камчатки.
    if (prevLon !== null && Math.abs(ll[0] - prevLon) > 180) {
      if (run.length > 1) runs.push(run);
      run = [];
    }
    prevLon = ll[0];
    const p = proj(ll);
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
    this._wps = new Map();      // маршрут → его точки, считается в setData
    this._userTouched = false;  // юзер взял карту в руки — автофокус молчит
    this._focusRaf = null;
    this._focusing = false;

    // Глобус можно взять и покрутить в любую сторону.
    canvas.addEventListener('pointerdown', e => {
      this.drag = {x: e.clientX, y: e.clientY, rot: [...this.rotation], off: [...this.offset]};
      try { canvas.setPointerCapture(e.pointerId); } catch (_) {}
    });
    canvas.addEventListener('pointermove', e => {
      if (!this.drag) return;
      // Пользователь повёл карту сам — с этого момента автофокус не вправе
      // её отбирать: ручное управление уважается, как и раньше.
      this._userTouched = true;
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
      this._userTouched = true; // зум — тоже ручное управление
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
    // Обработчик хранится в поле: destroy() обязан его снять, иначе каждая
    // пересозданная карта оставляла бы в window слушателя-сироту.
    this._onResize = () => this.render();
    window.addEventListener('resize', this._onResize);
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
    // waypoints зависят только от данных: считаем их один раз здесь, а не
    // трижды на каждый кадр вращения (заливка обрыва, лучи, оверлей).
    this._wps = new Map();
    for (const r of this.data.routes || []) this._wps.set(r, waypoints(r));
    this.focusRoutes();
    this.render();
  }

  // wpsOf — мемоизированные точки маршрута. Незнакомому маршруту (данные
  // пришли мимо setData) отвечает честным пересчётом, а не пустотой.
  wpsOf(r) {
    let w = this._wps.get(r);
    if (!w) { w = waypoints(r); this._wps.set(r, w); }
    return w;
  }

  // focusRoutes наводит камеру на маршруты: пользователь и его лучи — в центре
  // внимания вместо стартового вида на Европу. Ручное управление сильнее:
  // карту, взятую в руки, автофокус не дёргает.
  focusRoutes() {
    if (this._userTouched) return;
    const pts = [];
    for (const wps of this._wps.values()) {
      if (wps.length < 2) continue; // одинокое «ты здесь» камеру не ведёт
      for (const w of wps) pts.push(w.at);
    }
    if (!pts.length) return;

    // Центр — среднее единичных векторов. У набора долгот по обе стороны
    // 180-го меридиана «середины» в арифметическом смысле нет, а у точек
    // на сфере она есть всегда.
    let x = 0, y = 0, z = 0;
    for (const [lon, lat] of pts) {
      const la = lat * Math.PI / 180, lo = lon * Math.PI / 180;
      x += Math.cos(la) * Math.cos(lo);
      y += Math.cos(la) * Math.sin(lo);
      z += Math.sin(la);
    }
    const len = Math.hypot(x, y, z);
    if (len < 1e-9) return; // точки равномерно по всей сфере — наводиться некуда
    const cLon = Math.atan2(y, x) * 180 / Math.PI;
    const cLat = Math.asin(z / len) * 180 / Math.PI;

    if (this.style === 'globe') {
      this._animateRotation([-cLon, Math.max(-85, Math.min(85, -cLat))]);
    } else {
      this._animateOffset([cLon, cLat]);
    }
  }

  // Плавный доворот глобуса к цели. Автовращение на время доворота молчит
  // (см. loop) и продолжается с новой точки: фокус подменяет стартовый вид,
  // а не пожелание пользователя.
  _animateRotation(to) {
    const from = [...this.rotation];
    let dLon = to[0] - from[0];
    dLon = ((dLon % 360) + 540) % 360 - 180; // короткой дугой, а не вокруг света
    const dLat = to[1] - from[1];
    const start = performance.now(), dur = 800;
    cancelAnimationFrame(this._focusRaf);
    this._focusing = true;
    const step = now => {
      const t = Math.min(1, (now - start) / dur);
      const e = t * (2 - t); // easeOutQuad: быстро стартует, мягко доезжает
      this.rotation = [from[0] + dLon * e, from[1] + dLat * e];
      this.render();
      if (t < 1 && !this._userTouched) {
        this._focusRaf = requestAnimationFrame(step);
      } else {
        this._focusing = false;
      }
    };
    this._focusRaf = requestAnimationFrame(step);
  }

  // Центрирование плоской карты: offset подводится так, чтобы центр маршрутов
  // встал в середину холста. При zoom = 1 карта видна целиком и projection()
  // всё равно зажимает сдвиг в ноль — фокусировать нечего.
  _animateOffset(center) {
    if (this.zoom === 1) return;
    const box = this.canvas.parentElement || this.canvas;
    const w = box.clientWidth, h = box.clientHeight;
    if (!w || !h) return;
    const pad = 10;
    const base = geoEquirectangular()
      .fitExtent([[pad, pad], [w - pad, h - pad]], {type: 'Sphere'});
    const p = base(center);
    if (!p) return;
    // экран = центр + zoom·(базовая точка − центр) + offset, поэтому чтобы
    // точка попала в центр холста: offset = −zoom·(базовая точка − центр).
    const to = [-(p[0] - w / 2) * this.zoom, -(p[1] - h / 2) * this.zoom];
    const from = [...this.offset];
    const start = performance.now(), dur = 800;
    cancelAnimationFrame(this._focusRaf);
    this._focusing = true;
    const step = now => {
      const t = Math.min(1, (now - start) / dur);
      const e = t * (2 - t);
      this.offset = [from[0] + (to[0] - from[0]) * e, from[1] + (to[1] - from[1]) * e];
      this.render(); // projection() сам удержит сдвиг в допустимых границах
      if (t < 1 && !this._userTouched) {
        this._focusRaf = requestAnimationFrame(step);
      } else {
        this._focusing = false;
      }
    };
    this._focusRaf = requestAnimationFrame(step);
  }

  loop() {
    cancelAnimationFrame(this.raf);
    const tick = () => {
      // пока камера доезжает до маршрутов, автовращение не тянет её вбок
      if (this.style === 'globe' && this.autoSpin && !this.drag && !this._focusing) {
        this.rotation[0] += 0.12;
        this.render();
      }
      this.raf = requestAnimationFrame(tick);
    };
    this.raf = requestAnimationFrame(tick);
  }

  destroy() {
    cancelAnimationFrame(this.raf);
    cancelAnimationFrame(this._focusRaf);
    // Наблюдатели переживают свой canvas, если их не снять: карта,
    // пересозданная при переключении вкладок, копила бы обработчиков.
    if (this.ro) this.ro.disconnect();
    window.removeEventListener('resize', this._onResize);
  }

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
        const wps = this.wpsOf(r);
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
      const wps = this.wpsOf(r);
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
    // Узлы оверлея переиспользуются между кадрами: на глобусе этот код
    // работает 60 раз в секунду, и innerHTML = '' с пересозданием десятков
    // <div> на каждый кадр кормил сборщик мусора вместо вращения. Курсор
    // идёт по уже существующим детям, лишние срезаются в самом конце.
    let cursor = 0;
    const take = cls => {
      let el = ov.children[cursor];
      if (!el) { el = document.createElement('div'); ov.appendChild(el); }
      cursor++;
      // В прошлом кадре узел мог играть другую роль — чистим всё, что
      // ставится не всегда: текст, подсказку и геометрию выносок.
      el.className = cls;
      if (el.textContent) el.textContent = '';
      if (el.title) el.title = '';
      el.style.width = '';
      el.style.transform = '';
      return el;
    };
    ov.style.width = w + 'px';
    ov.style.height = h + 'px';

    // на глобусе точки обратной стороны прятать обязательно, иначе Сидней
    // окажется поверх Атлантики
    const center = [-this.rotation[0], -this.rotation[1]];
    const visible = (lon, lat) =>
      this.style !== 'globe' || angularDistance(center, [lon, lat]) < 89;

    // При увеличении часть точек уезжает за край холста. Их отметки браузер
    // просто не показывал, а подписи оставались — и висели поверх интерфейса
    // рядом с картой, привязанные к невидимому. Точки за краем не рисуем вовсе.
    const onCanvas = p => p && isFinite(p[0]) && isFinite(p[1]) &&
      p[0] >= 0 && p[0] <= w && p[1] >= 0 && p[1] <= h;

    // put больше не добавляет узел в DOM — этим занимается take: узел уже
    // на месте, меняются только координаты.
    const put = (el, x, y) => {
      el.style.left = x + 'px';
      el.style.top = y + 'px';
    };

    // Концы лучей группируются по стране и исходу: до одной и той же точки
    // обрыва приходит десяток сервисов, и десять отметок друг на друге
    // не сказали бы ничего сверх одной с числом.
    const labels = this.data.labels || {};
    const ends = new Map();
    for (const r of this.data.routes || []) {
      const wps = this.wpsOf(r);
      // Одна точка — это только «ты здесь»: ни одного шага разместить
      // не удалось, и говорить про такой маршрут на карте нечего.
      if (wps.length < 2) continue;
      const last = wps[wps.length - 1];
      // Порядок важен: «пакеты дошли, а сервис не работает» — это блокировка,
      // и назвать её «маршрут дошёл» значило бы противоречить отчёту,
      // где тот же сервис помечен недоступным.
      const kind = r.opaque ? 'dim'
        : !r.reached ? 'break'
        : r.serviceOK === false ? 'blocked'
        : r.farCountry ? 'pop' : 'ok';
      // Одно место и один оператор — одна отметка. Разбивать её ещё и по
      // исходу нельзя: у одного узла и доходящие маршруты, и оборвавшиеся,
      // и тогда в один пиксель ложились три значка друг на друга, а рядом
      // вставали две одинаковые подписи. Значок берётся по худшему исходу,
      // остальное рассказывает подсказка.
      const owner = last.node && last.node.org
        ? `AS${last.node.asn} ${last.node.org}`
        : (last.node && last.node.ip) || last.code;
      const key = last.code + '|' + owner;
      let g = ends.get(key);
      if (!g) {
        g = {at: last.at, code: last.code, owner, kind, node: last.node,
          hosts: [], notes: new Set(), kinds: new Set()};
        ends.set(key, g);
      }
      if (SEVERITY.indexOf(kind) > SEVERITY.indexOf(g.kind)) g.kind = kind;
      g.kinds.add(kind);
      g.hosts.push(r.host);
      if (r.note) g.notes.add(r.note);
    }

    // Подписи собираются списком и раскладываются одним заходом в самом конце.
    //
    // Раскладывать их по одной, сдвигая каждую следующую вниз, пока не
    // освободится место, бесполезно: концы лучей сбиваются в Европу — десяток
    // точек на сотню пикселей, — и столбец подписей уезжал в Индийский океан,
    // где всё равно ложился сам на себя, упёршись в ограничитель сдвига.
    // Вместо этого подпись, которой не хватило места у своей точки, выносится
    // в столбец у ближнего края карты и соединяется с ней выноской. Это
    // обычная картографическая выноска, и она читается.
    const want = [];

    // В один и тот же узел связи приходят разные операторы — до московского
    // сходятся и Ростелеком, и Яндекс, и Cloudflare, — и значки ложились
    // в один пиксель, где виден оставался последний. Разводим их короткой
    // спиралью: несколько пикселей на карте мира ничего не искажают, зато
    // видно, что точка тут не одна.
    const used = [];
    const spread = p => {
      let x = p[0], y = p[1];
      for (let k = 1; used.some(u => Math.hypot(u[0] - x, u[1] - y) < 9); k++) {
        const r = 7 + k * 1.6;
        x = p[0] + Math.cos(k * 1.9) * r;
        y = p[1] + Math.sin(k * 1.9) * r;
      }
      used.push([x, y]);
      return [x, y];
    };

    for (const g of ends.values()) {
      if (!visible(g.at[0], g.at[1])) continue;
      const raw = proj(g.at);
      if (!onCanvas(raw)) continue;
      const p = spread(raw);

      const owner = g.owner;

      const mark = take(g.kind === 'break' ? 'mx'
        : g.kind === 'pop' ? 'mpop'
        : g.kind === 'dim' ? 'mdim'
        : g.kind === 'blocked' ? 'mdot bad'
        : 'mdot ok');
      mark.title = [
        `${[...g.kinds].map(k => labels[k] || k).join(' / ')}: ${owner}`,
        g.hosts.join(', '),
        ...g.notes,
      ].filter(Boolean).join('\n');
      put(mark, p[0], p[1]);

      want.push({
        p,
        text: g.hosts.length > 1 ? `${owner} · ${g.hosts.length}` : owner,
        cls: 'mlab' + (g.kind === 'break' ? ' bad' : ''),
      });
    }

    const pin = (info, cls, label) => {
      if (!info || (!info.lat && !info.lon)) return null;
      if (!visible(info.lon, info.lat)) return null;
      const raw = proj([info.lon, info.lat]);
      if (!onCanvas(raw)) return null;
      const p = spread(raw);
      const el = take('mpin ' + cls);
      el.title = `${label}: ${info.city || ''} ${info.country || ''} ${info.ip || ''}`.trim();
      put(el, p[0], p[1]);
      // «Ты здесь» и «выход VPN» встают в общую очередь: они ложатся ровно
      // туда же, куда и подписи лучей, и разводить их отдельно нечестно.
      want.push({p, text: `${label}: ${info.city || info.country || info.ip || ''}`,
        cls: 'mlab pin', first: true});
      return p;
    };

    const a = pin(this.data.geoDirect, 'here', labels.here || 'you');
    const b = pin(this.data.geoProxy, 'vpn', labels.vpn || 'VPN');
    this.layOutLabels(want, w, h, put, take);
    if (a && b) {
      const line = take('mline');
      const dx = b[0] - a[0], dy = b[1] - a[1];
      line.style.left = a[0] + 'px';
      line.style.top = a[1] + 'px';
      line.style.width = Math.hypot(dx, dy) + 'px';
      line.style.transform = `rotate(${Math.atan2(dy, dx)}rad)`;
    }
    // хвост от прошлого кадра: точек могло стать меньше
    while (ov.children.length > cursor) ov.removeChild(ov.lastChild);
  }

  // layOutLabels раскладывает подписи так, чтобы каждую можно было прочесть
  // и понять, к какой она точке.
  //
  // Сначала подпись пробуют поставить рядом с её точкой. Если там уже занято,
  // она уходит в столбец у ближнего края карты, а к точке от неё тянется
  // выноска. Столбец упакован сверху вниз в порядке высоты точек — так линии
  // выносок не перепутываются между собой.
  //
  // Ширину меряем на глаз, по числу знаков: настоящий замер через offsetWidth
  // заставляет браузер пересчитывать раскладку, а этот код на глобусе
  // работает шестьдесят раз в секунду.
  layOutLabels(items, w, h, put, take) {
    // CH — ширина знака шрифта подписей: моноширинный, 9.5 px, около 5.7 px
    // на знак. Берём чуть с запасом: недомер ширины означает, что две подписи
    // «не пересекаются» по расчёту и ложатся друг на друга на экране.
    const ROW = 14, CH = 5.8, PAD = 8;
    const wide = t => t.length * CH + 4;
    const boxes = [];
    const fits = (x, y, bw) => !boxes.some(b =>
      x < b.x + b.w && b.x < x + bw && Math.abs(b.y - y) < ROW - 2);

    // «Ты здесь» и «выход VPN» ставятся первыми: это опора всей карты,
    // и уводить их в столбец, пока рядом есть место, незачем.
    const order = [...items.keys()].sort((i, j) =>
      (items[j].first ? 1 : 0) - (items[i].first ? 1 : 0) || items[i].p[1] - items[j].p[1]);

    const spill = [];
    for (const i of order) {
      const it = items[i];
      const bw = wide(it.text);
      // у правого края подпись уходит влево, иначе её срезает границей окна
      const left = it.p[0] + bw + 12 > w - PAD;
      const x = left ? it.p[0] - 9 - bw : it.p[0] + 9;
      const y = it.p[1] - 7;
      if (x >= PAD && fits(x, y, bw)) {
        boxes.push({x, y, w: bw});
        const el = take(it.cls + (left ? ' left' : ''));
        el.textContent = it.text;
        put(el, it.p[0] + (left ? -9 : 9), y);
      } else {
        spill.push(it);
      }
    }
    if (!spill.length) return;

    // Столбец: каждая подпись у того края, к которому её точка ближе.
    for (const side of ['left', 'right']) {
      const col = spill.filter(it => (it.p[0] < w / 2) === (side === 'left'))
        .sort((a, b) => a.p[1] - b.p[1]);
      let y = PAD;
      for (const it of col) {
        y = Math.min(Math.max(y, it.p[1] - 7), h - PAD - ROW);
        const bw = wide(it.text);
        const x = side === 'left' ? PAD : w - PAD - bw;
        const el = take(it.cls);
        el.textContent = it.text;
        put(el, x, y);
        // Выноска от точки к началу строки. Без неё столбец из семи строк —
        // просто список, по которому не понять, что к чему относится.
        const tip = side === 'left' ? x + bw + 3 : x - 3;
        const dx = tip - it.p[0], dy = (y + 6) - it.p[1];
        const len = Math.hypot(dx, dy);
        if (len > 10) {
          const l = take('mlead');
          l.style.width = len + 'px';
          l.style.transform = `rotate(${Math.atan2(dy, dx)}rad)`;
          put(l, it.p[0], it.p[1]);
        }
        y += ROW;
      }
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
