// check-i18n.mjs — проверка полноты фронтендового словаря.
// Запуск: node check-i18n.mjs (из каталога frontend). В pipeline не встроен.
//
// Что проверяется:
//   1) у каждого ключа STR в src/i18n.js есть непустые ru и en,
//      и плейсхолдеры (%n, %t и т.п.) совпадают между языками;
//   2) каждый литеральный ключ t('...') из src/main.js существует в STR;
//   3) каждая база pl(n, '...') имеет формы .one/.few/.many;
//   4) каждый data-i18n / data-i18n-title / data-i18n-ph из index.html
//      существует в STR.
// Динамические ключи (t('layer.' + l), t(key)) не проверяются: их не
// собрать без исполнения кода, а ложная тревога хуже пробела.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const src = f => readFileSync(join(root, f), 'utf8');

const i18nSrc = src('src/i18n.js');
const mainSrc = src('src/main.js');
const htmlSrc = src('index.html');

let failures = 0;
const fail = msg => { failures++; console.error('FAIL: ' + msg); };

/* ── 1. словарь: ключ → {ru, en} ── */
// Значения — плоские объекты без вложенных фигурных скобок, поэтому
// достаточно нежадного захвата до первой '}'.
const dict = new Map();
for (const m of i18nSrc.matchAll(/'([A-Za-z0-9_.]+)'\s*:\s*\{([^}]*)\}/gs)) {
  dict.set(m[1], m[2]);
}
if (dict.size === 0) fail('словарь не распарсился — проверь src/i18n.js');

const strOf = (block, lang) => {
  const m = block.match(new RegExp(lang + String.raw`\s*:\s*'((?:[^'\\]|\\.)*)'`, 's'));
  return m ? m[1] : null;
};
const placeholders = s => (s.match(/%[a-z]/g) || []).sort().join(',');

for (const [key, block] of dict) {
  const ru = strOf(block, 'ru');
  const en = strOf(block, 'en');
  if (!ru) fail(`${key}: нет русского текста`);
  if (!en) fail(`${key}: нет английского текста`);
  if (ru && en && placeholders(ru) !== placeholders(en)) {
    fail(`${key}: плейсхолдеры расходятся: ru=[${placeholders(ru)}] en=[${placeholders(en)}]`);
  }
}

/* ── 2. литеральные вызовы t('...') из main.js ── */
const used = new Set();
for (const m of mainSrc.matchAll(/\bt\(\s*'([A-Za-z0-9_.]+)'\s*\)/g)) used.add(m[1]);
// тернарные вызовы: t(cond ? 'a' : 'b')
for (const m of mainSrc.matchAll(/\bt\([^()]*\?\s*'([A-Za-z0-9_.]+)'\s*:\s*'([A-Za-z0-9_.]+)'\s*\)/g)) {
  used.add(m[1]); used.add(m[2]);
}
for (const key of used) {
  if (!dict.has(key)) fail(`main.js использует t('${key}'), а ключа в словаре нет`);
}

/* ── 3. базы множественного числа pl(n, '...') ── */
// первый аргумент бывает выражением со скобками — берём последний строковый
// литерал перед закрывающей скобкой вызова
for (const m of mainSrc.matchAll(/\bpl\(.*?'([A-Za-z0-9_.]+)'\s*\)/g)) {
  for (const suf of ['.one', '.few', '.many']) {
    if (!dict.has(m[1] + suf)) fail(`pl-база '${m[1]}': нет формы ${m[1]}${suf}`);
  }
}

/* ── 4. статические подписи из index.html ── */
for (const m of htmlSrc.matchAll(/data-i18n(?:-title|-ph)?="([A-Za-z0-9_.]+)"/g)) {
  if (!dict.has(m[1])) fail(`index.html ссылается на '${m[1]}', а ключа в словаре нет`);
}

if (failures) {
  console.error(`\n${failures} problem(s) found`);
  process.exit(1);
}
console.log(`OK: ${dict.size} ключей словаря, ${used.size} литеральных t(...) из main.js — всё сходится`);
