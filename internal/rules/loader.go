package rules

import (
	"os"
	"path/filepath"
	"sort"
)

// LoadResult is the outcome of loading a rules directory.
type LoadResult struct {
	Compiled *Compiled
	Rejected []*FileError
}

// LoadDir reads every *.json file directly under dir (non-recursive) and
// compiles them into a rule set. A missing/unreadable directory is reported as
// a read rejection and yields an empty (but valid) rule set.
func LoadDir(dir string) LoadResult {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return LoadResult{
			Compiled: &Compiled{Version: emptyVersion},
			Rejected: []*FileError{{File: dir, Reason: ReasonReadError, Err: err}},
		}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	b := &Bundle{}
	var rejected []*FileError
	for _, n := range names {
		full := filepath.Join(dir, n)
		data, err := os.ReadFile(full)
		if err != nil {
			rejected = append(rejected, &FileError{File: n, Reason: ReasonReadError, Err: err})
			continue
		}
		f, fe := rawFile(n, data)
		if fe != nil {
			rejected = append(rejected, fe)
			continue
		}
		b.Add(n, f)
	}
	compiled, compileRejects := b.Compile()
	rejected = append(rejected, compileRejects...)
	if len(compiled.Rules) == 0 {
		compiled.Version = emptyVersion
	}
	return LoadResult{Compiled: compiled, Rejected: rejected}
}
