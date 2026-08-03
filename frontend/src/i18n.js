// i18n — статические подписи интерфейса RU/EN.
// Строки вердикта приходят с бэкенда уже локализованными — их тут нет.

export const STR = {
  // шапка
  'app.tagline':   {ru: 'диагностика интернета', en: 'internet diagnostics'},
  'lang.switch':   {ru: 'Язык интерфейса',       en: 'Interface language'},
  'gear.title':    {ru: 'Настройки', en: 'Settings'},

  // настройки
  'set.title':        {ru: 'Настройки',          en: 'Settings'},
  'map.spin.on':   {ru: '⏸ Вращение', en: '⏸ Spin'},
  'map.spin.off':  {ru: '▶ Вращение', en: '▶ Spin'},
  'map.spin.hint': {ru: 'Авто-вращение. Глобус можно крутить мышью и колесом (Shift — наклон)',
                    en: 'Auto-spin. Drag the globe or use the wheel (Shift tilts it)'},

  'map.style.globe':     {ru: 'Глобус', en: 'Globe'},
  'map.style.countries': {ru: 'Страны', en: 'Countries'},
  'map.style.dots':      {ru: 'Точки',  en: 'Dots'},

  'set.lang':         {ru: 'Язык',               en: 'Language'},
  'set.scale':        {ru: 'Размер интерфейса',  en: 'Interface size'},
  'set.scale_s':      {ru: 'Мелкий',             en: 'Small'},
  'set.scale_m':      {ru: 'Средний',            en: 'Medium'},
  'set.scale_l':      {ru: 'Крупный',            en: 'Large'},
  'set.scale_xl':     {ru: 'Очень крупный',      en: 'Extra large'},
  'set.font_hud':     {ru: 'Шрифт заголовков',   en: 'Heading font'},
  'set.font_mono':    {ru: 'Шрифт данных',       en: 'Data font'},
  'set.font_file':    {ru: 'Файл шрифта',        en: 'Font file'},
  'set.font_file_ph': {ru: 'C:\\путь\\к\\шрифту.ttf', en: 'C:\\path\\to\\font.ttf'},
  'set.font_default': {ru: '— по умолчанию —',   en: '— default —'},
  'set.font_note':    {
    ru: 'Файл .ttf/.otf можно взять с диска, не устанавливая шрифт в систему — он подставляется в интерфейс на лету и имеет приоритет над выбранным семейством.',
    en: 'A .ttf/.otf file can be used straight from disk without installing it — it is inlined into the UI at runtime and takes priority over the selected family.',
  },
  'set.save':         {ru: 'Сохранить', en: 'Save'},
  'set.cancel':       {ru: 'Отмена',    en: 'Cancel'},

  // кнопка
  'btn.run':       {ru: 'Проверить',       en: 'Run check'},
  'btn.running':   {ru: 'Идёт проверка…',  en: 'Checking…'},
  'btn.lastrun':   {ru: 'последний прогон', en: 'last run'},
  'btn.norun':     {ru: 'ещё не запускалась', en: 'no runs yet'},

  // панели
  'panel.env':     {ru: 'Окружение',        en: 'Environment'},
  'panel.history': {ru: 'История прогонов', en: 'Run history'},
  'panel.verdict': {ru: 'Вердикт',          en: 'Verdict'},
  'panel.tests':   {ru: 'Тесты',            en: 'Tests'},

  // окружение
  'env.net':       {ru: 'Сеть',   en: 'Network'},
  'env.gateway':   {ru: 'Шлюз',   en: 'Gateway'},
  'env.ip':        {ru: 'IP',     en: 'IP'},
  'env.vpn':       {ru: 'VPN-признаки', en: 'VPN signs'},
  'env.proxy':     {ru: 'прокси', en: 'proxy'},
  'env.sysproxy':  {ru: 'Сист. прокси Windows', en: 'Windows system proxy'},
  'env.tunnels':   {ru: 'Туннель-адаптеры', en: 'Tunnel adapters'},
  'env.tailscale': {ru: 'Tailscale', en: 'Tailscale'},
  'env.defroute':  {ru: 'маршрут по умолчанию', en: 'default route'},
  'val.on':        {ru: 'вкл',     en: 'on'},
  'val.off':       {ru: 'выкл',    en: 'off'},
  'val.none':      {ru: 'нет',     en: 'none'},
  'val.active':    {ru: 'активен', en: 'active'},

  // слои (цепочка вердикта)
  'layer.gateway': {ru: 'Шлюз',      en: 'Gateway'},
  'layer.dns':     {ru: 'DNS',       en: 'DNS'},
  'layer.runet':   {ru: 'Рунет',     en: 'RuNet'},
  'layer.global':  {ru: 'Заграница', en: 'Global'},
  'layer.blocked': {ru: 'Блокируемые сервисы', en: 'Blocked services'},
  // короткое имя слоя для колонки таблицы
  'tlayer.blocked':{ru: 'Сервисы',   en: 'Services'},

  // таблица
  'col.layer':     {ru: 'Слой',      en: 'Layer'},
  'col.target':    {ru: 'Цель',      en: 'Target'},
  'col.method':    {ru: 'Метод',     en: 'Method'},
  'col.path':      {ru: 'Путь',      en: 'Path'},
  'col.time':      {ru: 'Время',     en: 'Time'},
  'col.result':    {ru: 'Результат', en: 'Result'},
  'path.direct':   {ru: 'напрямую',  en: 'direct'},
  'path.proxy':    {ru: 'прокси',    en: 'proxy'},
  'table.empty':   {ru: 'Нет данных — запустите проверку.', en: 'No data — run a check.'},

  // счётчики (формы множественного числа)
  'cnt.checks.one':  {ru: 'проверка',  en: 'check'},
  'cnt.checks.few':  {ru: 'проверки',  en: 'checks'},
  'cnt.checks.many': {ru: 'проверок',  en: 'checks'},
  'cnt.layers.one':  {ru: 'слой',      en: 'layer'},
  'cnt.layers.few':  {ru: 'слоя',      en: 'layers'},
  'cnt.layers.many': {ru: 'слоёв',     en: 'layers'},

  // вердикт / состояния
  'verdict.empty':   {ru: 'Нажмите «Проверить», чтобы запустить диагностику.',
                      en: 'Press “Run check” to start diagnostics.'},
  'verdict.running': {ru: 'Идёт проверка…', en: 'Checking…'},
  'err.run':         {ru: 'Ошибка прогона', en: 'Run failed'},
  'hint.lang':       {ru: 'Текст вердикта обновится на выбранном языке при следующей проверке.',
                      en: 'The verdict text will switch to the selected language on the next run.'},

  // история
  'hist.empty':      {ru: 'нет данных', en: 'no data'},
  'hist.open':       {ru: 'Открыть этот прогон', en: 'Open this run'},
  'hist.yesterday':  {ru: 'вчера',      en: 'yest.'},

  // единицы
  'unit.ms':         {ru: 'мс', en: 'ms'},
  'unit.s':          {ru: 'с',  en: 's'},

  // вкладки
  'tab.report':      {ru: 'Отчёт', en: 'Report'},
  'tab.map':         {ru: 'Карта', en: 'Map'},

  // карта
  'map.title':       {ru: 'Куда доходит трафик', en: 'How far traffic gets'},
  'map.empty':       {ru: 'Нажмите «Проверить»', en: 'Press “Run check”'},
  'map.nolink':      {ru: 'нет связи', en: 'no link'},
  'map.legend.ok':   {ru: 'маршрут дошёл до цели', en: 'route reached the target'},
  'map.legend.warn': {ru: 'ответила ближайшая точка присутствия CDN', en: 'answered by the nearest CDN edge'},
  'map.legend.fail': {ru: 'путь оборвался здесь', en: 'path broke here'},
  'map.legend.you':  {ru: 'ты здесь', en: 'you are here'},
  'map.legend.vpn':  {ru: 'выход VPN', en: 'VPN exit'},
  'map.note.cdn':    {
    ru: 'Рисуется маршрут до цели, а не «страна сервиса». У сервиса за CDN страны нет: отвечает ближайшая точка присутствия, и покрасить за это США значило бы обманывать себя. Зато измеримо, до какого места дошли пакеты — оно и отмечено. Точность бесплатных геобаз — страна, поэтому все шаги внутри одной страны показаны одной отметкой.',
    en: 'What is drawn is the route to the target, not the “country of the service”. A service behind a CDN has no country: the nearest edge answers, and painting the US for that would be lying to yourself. What is measurable is how far the packets got — that is what gets marked. Free geo databases resolve to country at best, so every hop inside one country is shown as a single mark.',
  },
  'map.geo.you':     {ru: 'ты здесь', en: 'you are here'},
  'map.geo.vpn':     {ru: 'выход VPN', en: 'VPN exit'},
  'map.geo.off':     {ru: 'Определение страны выхода выключено в настройках.',
                      en: 'Exit-country detection is disabled in settings.'},
  'map.sum.reached': {ru: 'маршрутов дошло', en: 'routes completed'},
  'map.sum.brokeAt': {ru: 'чаще всего обрывается у', en: 'most often breaks at'},
  'map.sum.from':    {ru: 'смотрим из', en: 'looking from'},
  'map.sum.exit':    {ru: 'трафик выходит из', en: 'traffic exits from'},

  'map.mark.break':  {ru: 'путь оборвался здесь', en: 'path broke here'},
  'map.mark.pop':    {ru: 'ближайшая точка присутствия', en: 'nearest point of presence'},
  'map.mark.ok':     {ru: 'маршрут дошёл', en: 'route completed'},
  'map.mark.dim':    {ru: 'сервис отвечает, но маршрут дальше не виден — режут ICMP',
                      en: 'the service answers, but the route is not traceable — ICMP is filtered'},

  // настройки карты
  'set.show_map':    {ru: 'Показывать карту', en: 'Show map'},
  'set.geo_lookup':  {ru: 'Определять страну выхода (запрос к внешнему сервису)',
                      en: 'Detect exit country (external service request)'},
  'set.geo_note':    {
    ru: 'Определение страны выхода — единственное место, где приложение сообщает наружу твой IP-адрес.',
    en: 'Exit-country detection is the only place where the app reveals your IP address to the outside.',
  },
};

/* ── общий счёт прогона ── */
Object.assign(STR, {
  'tally.ok': {ru: 'ОК', en: 'ok'},
  'tally.warn': {ru: 'медленно', en: 'slow'},
  'tally.skip': {ru: 'пропущено', en: 'skipped'},
  'cnt.fails.one': {ru: 'ошибка', en: 'failed'},
  'cnt.fails.few': {ru: 'ошибки', en: 'failed'},
  'cnt.fails.many': {ru: 'ошибок', en: 'failed'},
  'tally.services': {ru: 'сервисов работает', en: 'services working'},
});

/* ── вкладка «Сервисы» ── */
Object.assign(STR, {
  'tab.services': {ru: 'Сервисы', en: 'Services'},
  'svc.title': {ru: 'Что проверять', en: 'What to check'},
  'svc.preset.quick': {ru: 'Быстрый', en: 'Quick'},
  'svc.preset.standard': {ru: 'Стандартный', en: 'Standard'},
  'svc.preset.blocked': {ru: 'Блокируемые', en: 'Blocked'},
  'svc.preset.all': {ru: 'Все', en: 'All'},
  'svc.preset.none': {ru: 'Ничего', en: 'None'},
  'svc.search_ph': {ru: 'Поиск по названию или адресу', en: 'Search by name or host'},
  'svc.custom_ph': {ru: 'свой адрес, например example.com', en: 'your own host, e.g. example.com'},
  'svc.add': {ru: 'Добавить', en: 'Add'},
  'svc.remove': {ru: 'Убрать из списка', en: 'Remove from the list'},
  'svc.own': {ru: 'своя цель', en: 'your own target'},
  'svc.selected': {ru: 'выбрано %n из %t', en: '%n of %t selected'},
  'svc.nothing': {
    ru: 'Ничего не выбрано — проверять будет нечего.',
    en: 'Nothing selected — there will be nothing to check.',
  },
  'svc.note': {
    ru: 'Выбор сохраняется сразу. Чем длиннее список, тем дольше прогон: каждая цель — это отдельная цепочка проверок.',
    en: 'Choices save immediately. The longer the list, the longer a run takes: every target is its own chain of probes.',
  },
  'svc.none_found': {ru: 'Ничего не нашлось', en: 'Nothing found'},
  'grp.runet': {ru: 'Рунет и СНГ', en: 'RuNet and CIS'},
  'grp.global': {ru: 'Заграница', en: 'Global'},
  'grp.blocked': {ru: 'Блокируемые', en: 'Blocked here'},
  'grp.geo': {ru: 'Геоблок', en: 'Geo-blocked'},
  'grp.runet.hint': {
    ru: 'живы ли местные сервисы и не сломал ли их VPN',
    en: 'are local services alive, and did the VPN break them',
  },
  'grp.global.hint': {
    ru: 'то, что никто не режет — эталон связности',
    en: 'what nobody blocks — the connectivity yardstick',
  },
  'grp.blocked.hint': {
    ru: 'то, что режет провайдер',
    en: 'what your ISP blocks',
  },
  'grp.geo.hint': {
    ru: 'сервис сам не пускает по стране IP',
    en: 'the service itself refuses your country',
  },
});

let lang = 'ru';

export function getLang() { return lang; }

export function t(key) {
  const e = STR[key];
  if (!e) return key;
  return e[lang] ?? e.ru ?? key;
}

// applyLang проставляет язык и обновляет все статические подписи [data-i18n].
export function applyLang(l) {
  lang = (l === 'en') ? 'en' : 'ru';
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    el.title = t(el.dataset.i18nTitle);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    el.placeholder = t(el.dataset.i18nPh);
  });
}

// plural — правильная форма слова для счётчика: pl(3,'cnt.checks') → «проверки».
export function pl(n, base) {
  if (lang === 'en') return t(base + (n === 1 ? '.one' : '.many'));
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return t(base + '.one');
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return t(base + '.few');
  return t(base + '.many');
}
