//go:build windows

package fonts

import (
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// имена в реестре выглядят как "Arial Bold (TrueType)" / "Consolas (OpenType)"
var suffixRe = regexp.MustCompile(`\s*\((TrueType|OpenType|VGA res|All res)[^)]*\)$`)

// List — установленные семейства шрифтов (машинные + пользовательские),
// без дублей, по алфавиту.
func List() []string {
	seen := map[string]struct{}{}
	for _, k := range []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts`},
	} {
		key, err := registry.OpenKey(k.root, k.path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, err := key.ReadValueNames(0)
		key.Close()
		if err != nil {
			continue
		}
		for _, n := range names {
			fam := trimStyles(strings.TrimSpace(suffixRe.ReplaceAllString(n, "")))
			if fam == "" {
				continue
			}
			seen[fam] = struct{}{}
		}
	}

	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
