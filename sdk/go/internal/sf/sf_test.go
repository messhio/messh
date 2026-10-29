package sf_test

import (
	"testing"

	"messh.io/go/messh/internal/sf"
	"messh.io/go/messh/internal/vectors"
)

func TestStructuredFieldVectors(t *testing.T) {
	doc, ok := vectors.Load()
	if !ok {
		t.Skip("vectors live in the messh repo (spec/vectors)")
	}
	for _, c := range doc.StructuredFields {
		var got string
		var err error
		switch c.Type {
		case "dictionary":
			var d sf.Dictionary
			d, _, err = sf.ParseDictionary(c.Input)
			got = d.String()
		case "list":
			var l []sf.Member
			l, err = sf.ParseList(c.Input)
			got = sf.SerializeList(l)
		default:
			var it sf.Item
			it, err = sf.ParseItem(c.Input)
			got = it.String()
		}
		switch {
		case c.Error && err == nil:
			t.Errorf("%s: parsed %q, want an error", c.Name, c.Input)
		case !c.Error && err != nil:
			t.Errorf("%s: %v", c.Name, err)
		case !c.Error && got != c.Canonical:
			t.Errorf("%s: got %q, want %q", c.Name, got, c.Canonical)
		}
	}
}
