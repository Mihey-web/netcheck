package probe

import "testing"

func TestSameIPSet(t *testing.T) {
	if !SameIPSet([]string{"1.2.3.4", "5.6.7.8"}, []string{"5.6.7.8"}) {
		t.Fatal("overlapping sets must be equal")
	}
	if SameIPSet([]string{"1.2.3.4"}, []string{"9.9.9.9"}) {
		t.Fatal("disjoint sets must differ")
	}
	if SameIPSet(nil, []string{"1.1.1.1"}) {
		t.Fatal("empty vs non-empty must differ")
	}
}
