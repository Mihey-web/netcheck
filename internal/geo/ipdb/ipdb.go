// Package ipdb — офлайн-справочник «IPv4 → страна, автономная система».
//
// Зачем свой формат, а не готовый MMDB. Нужны ровно три поля: код страны,
// номер AS и её имя. MMDB несёт заметно больше и весит 17 МБ на две базы;
// то же самое в упакованном виде — около 3 МБ, а бинарник у netcheck один
// и его качают руками.
//
// Устройство простое: две отсортированные таблицы диапазонов, поиск —
// двоичный. Дырки в покрытии кодируются пустой записью, поэтому «адреса нет
// в базе» и «адрес принадлежит стране X» различимы, и на приватный адрес
// домашнего роутера база честно отвечает «не знаю» вместо выдумки.
//
// Только IPv4 — сознательно. Пробы netcheck ходят по A-записям, трассировка
// внутри РФ идёт по IPv4, а поддержка v6 удвоила бы размер ради данных,
// которыми некому пользоваться.
//
// Данные: DB-IP IP-to-Country Lite и DB-IP ASN Lite (CC BY 4.0, https://db-ip.com).
// Собирается генератором cmd/geogen.
package ipdb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

const (
	magic   = "NCGEO1"
	version = 1
	// headerLen — magic(6) + версия(1) + резерв(1) + три счётчика по 4.
	headerLen = 8 + 12

	countryRec = 4 + 2     // start, упакованный код
	asnRec     = 4 + 4 + 4 // start, номер AS, смещение имени
)

// Country — диапазон адресов одной страны. Границы включительные,
// порядок хостовый (1.0.0.0 == 0x01000000).
type Country struct {
	Start, End uint32
	Code       string // ISO alpha-2
}

// ASN — диапазон адресов одной автономной системы.
type ASN struct {
	Start, End uint32
	Number     uint32
	Org        string
}

// Record — что известно про адрес. Нули означают «в базе нет»,
// а не «нет страны» и не «ничей адрес».
type Record struct {
	Country string
	ASN     uint32
	Org     string
}

// DB — открытая база. Только чтение, потокобезопасна.
type DB struct {
	cStart []uint32
	cCode  []uint16 // 0 — дырка в покрытии

	aStart []uint32
	aNum   []uint32 // 0 — дырка в покрытии
	aName  []uint32 // смещение в names

	names string
	n     int // сколько непустых диапазонов, для Len
}

// Build пишет базу. Диапазоны обязаны идти по возрастанию и не пересекаться:
// молча склеивать чужие данные — верный способ потом объяснять пользователю,
// что его провайдер находится в Парагвае.
func Build(w io.Writer, cs []Country, as []ASN) error {
	if err := checkCountries(cs); err != nil {
		return err
	}
	if err := checkASNs(as); err != nil {
		return err
	}

	cTable := make([]byte, 0, (len(cs)*2+1)*countryRec)
	for i, c := range cs {
		if gap, ok := gapBefore(i, c.Start, cs[max(i-1, 0)].End); ok {
			cTable = appendCountry(cTable, gap, 0)
		}
		cTable = appendCountry(cTable, c.Start, packCode(c.Code))
	}
	if n := len(cs); n > 0 && cs[n-1].End != ^uint32(0) {
		cTable = appendCountry(cTable, cs[n-1].End+1, 0)
	}

	// Имена автономных систем повторяются тысячами диапазонов: в пул кладём
	// по одному разу.
	var names []byte
	offset := map[string]uint32{}
	intern := func(s string) uint32 {
		if off, ok := offset[s]; ok {
			return off
		}
		off := uint32(len(names))
		offset[s] = off
		names = append(names, s...)
		names = append(names, 0)
		return off
	}

	aTable := make([]byte, 0, (len(as)*2+1)*asnRec)
	for i, a := range as {
		if gap, ok := gapBefore(i, a.Start, as[max(i-1, 0)].End); ok {
			aTable = appendASN(aTable, gap, 0, 0)
		}
		aTable = appendASN(aTable, a.Start, a.Number, intern(a.Org))
	}
	if n := len(as); n > 0 && as[n-1].End != ^uint32(0) {
		aTable = appendASN(aTable, as[n-1].End+1, 0, 0)
	}

	head := make([]byte, headerLen)
	copy(head, magic)
	head[len(magic)] = version
	binary.LittleEndian.PutUint32(head[8:], uint32(len(cTable)/countryRec))
	binary.LittleEndian.PutUint32(head[12:], uint32(len(aTable)/asnRec))
	binary.LittleEndian.PutUint32(head[16:], uint32(len(names)))

	for _, part := range [][]byte{head, cTable, aTable, names} {
		if _, err := w.Write(part); err != nil {
			return err
		}
	}
	return nil
}

// gapBefore — нужна ли пустая запись перед диапазоном, начинающимся на start.
// Перед первым диапазоном она нужна, если тот начинается не с нуля; между
// соседними — если между ними есть незанятые адреса.
func gapBefore(i int, start, prevEnd uint32) (uint32, bool) {
	if i == 0 {
		return 0, start > 0
	}
	return prevEnd + 1, start > prevEnd+1
}

func appendCountry(dst []byte, start uint32, code uint16) []byte {
	dst = binary.LittleEndian.AppendUint32(dst, start)
	return binary.LittleEndian.AppendUint16(dst, code)
}

func appendASN(dst []byte, start, num, nameOff uint32) []byte {
	dst = binary.LittleEndian.AppendUint32(dst, start)
	dst = binary.LittleEndian.AppendUint32(dst, num)
	return binary.LittleEndian.AppendUint32(dst, nameOff)
}

func checkCountries(cs []Country) error {
	var prevEnd uint32
	for i, c := range cs {
		if len(c.Code) != 2 || c.Code[0] < 'A' || c.Code[0] > 'Z' || c.Code[1] < 'A' || c.Code[1] > 'Z' {
			return fmt.Errorf("ipdb: диапазон %d: код страны %q не ISO alpha-2", i, c.Code)
		}
		if c.End < c.Start {
			return fmt.Errorf("ipdb: диапазон %d: конец раньше начала", i)
		}
		if i > 0 && c.Start <= prevEnd {
			return fmt.Errorf("ipdb: диапазон %d начинается на %d, а предыдущий кончился на %d", i, c.Start, prevEnd)
		}
		prevEnd = c.End
	}
	return nil
}

func checkASNs(as []ASN) error {
	var prevEnd uint32
	for i, a := range as {
		if a.Number == 0 {
			return fmt.Errorf("ipdb: диапазон %d: номер AS нулевой, а ноль означает «неизвестно»", i)
		}
		if a.End < a.Start {
			return fmt.Errorf("ipdb: диапазон %d: конец раньше начала", i)
		}
		if i > 0 && a.Start <= prevEnd {
			return fmt.Errorf("ipdb: диапазон %d начинается на %d, а предыдущий кончился на %d", i, a.Start, prevEnd)
		}
		prevEnd = a.End
	}
	return nil
}

func packCode(s string) uint16 { return uint16(s[0])<<8 | uint16(s[1]) }

func unpackCode(v uint16) string {
	if v == 0 {
		return ""
	}
	return string([]byte{byte(v >> 8), byte(v)})
}

// Open разбирает базу, собранную Build. Данные копируются в срезы:
// база живёт всё время работы программы, а исходный буфер после этого
// можно отдать сборщику мусора.
func Open(raw []byte) (*DB, error) {
	if len(raw) < headerLen {
		return nil, fmt.Errorf("ipdb: база обрезана: %d байт", len(raw))
	}
	if string(raw[:len(magic)]) != magic {
		return nil, fmt.Errorf("ipdb: не наш формат")
	}
	if v := raw[len(magic)]; v != version {
		return nil, fmt.Errorf("ipdb: версия формата %d, читать умеем %d", v, version)
	}

	nc := binary.LittleEndian.Uint32(raw[8:])
	na := binary.LittleEndian.Uint32(raw[12:])
	nn := binary.LittleEndian.Uint32(raw[16:])

	want := int64(headerLen) + int64(nc)*countryRec + int64(na)*asnRec + int64(nn)
	if int64(len(raw)) != want {
		return nil, fmt.Errorf("ipdb: заголовок обещает %d байт, а их %d", want, len(raw))
	}

	db := &DB{
		cStart: make([]uint32, nc),
		cCode:  make([]uint16, nc),
		aStart: make([]uint32, na),
		aNum:   make([]uint32, na),
		aName:  make([]uint32, na),
	}

	p := raw[headerLen:]
	for i := range db.cStart {
		db.cStart[i] = binary.LittleEndian.Uint32(p[i*countryRec:])
		db.cCode[i] = binary.LittleEndian.Uint16(p[i*countryRec+4:])
		if db.cCode[i] != 0 {
			db.n++
		}
	}

	p = p[int(nc)*countryRec:]
	for i := range db.aStart {
		db.aStart[i] = binary.LittleEndian.Uint32(p[i*asnRec:])
		db.aNum[i] = binary.LittleEndian.Uint32(p[i*asnRec+4:])
		db.aName[i] = binary.LittleEndian.Uint32(p[i*asnRec+8:])
		if db.aNum[i] != 0 {
			db.n++
		}
	}

	db.names = string(p[int(na)*asnRec:])
	return db, nil
}

// Lookup ищет адрес. Неизвестный адрес, IPv6 и приватный диапазон дают
// пустую запись — это ответ «не знаю», и вызывающий обязан его отличать
// от настоящего результата.
func (db *DB) Lookup(addr netip.Addr) Record {
	addr = addr.Unmap()
	if !addr.Is4() {
		return Record{}
	}
	a := addr.As4()
	v := binary.BigEndian.Uint32(a[:])

	var rec Record
	if i := find(db.cStart, v); i >= 0 {
		rec.Country = unpackCode(db.cCode[i])
	}
	if i := find(db.aStart, v); i >= 0 && db.aNum[i] != 0 {
		rec.ASN = db.aNum[i]
		rec.Org = db.name(db.aName[i])
	}
	return rec
}

// find — индекс последнего диапазона, начинающегося не позже v.
func find(starts []uint32, v uint32) int {
	i := sort.Search(len(starts), func(i int) bool { return starts[i] > v })
	return i - 1
}

func (db *DB) name(off uint32) string {
	if int(off) >= len(db.names) {
		return ""
	}
	s := db.names[off:]
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

// Len — сколько в базе непустых диапазонов. Ноль означает, что база
// собрана без данных, и карта обязана об этом сказать, а не молчать.
func (db *DB) Len() int { return db.n }
