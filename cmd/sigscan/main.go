// Command sigscan loads local signature rules and scans local files.
// Nothing is sent to any external service.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lechandonga/signature-detection-engine-go/engine"
)

func main() {
	rulesFlag := flag.String("rules", "", "comma-separated rule files, or @rules.txt for a list file")
	chunk := flag.Int("chunk-size", 4096, "streaming read chunk size in bytes")
	maxCache := flag.Int("max-cache-bytes", 0, "cap on continuation/cache memory in bytes; 0 = unbounded")
	verifyLen := flag.Int("verify-len", 4096, "bounded prefix bytes hashed before trusting a continuation")
	quiet := flag.Bool("quiet", false, "suppress per-file workload summary on stderr")
	reload := flag.Bool("reload", false, "load rules, print the rule report and exit")
	flag.Parse()

	paths := strings.FieldsFunc(*rulesFlag, func(r rune) bool { return r == ',' })
	if len(paths) == 1 && strings.HasPrefix(paths[0], "@") {
		data, err := os.ReadFile(strings.TrimPrefix(paths[0], "@"))
		if err != nil {
			fatal(err)
		}
		paths = strings.FieldsFunc(string(data), func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
		})
	}
	if len(paths) == 0 {
		fatal(fmt.Errorf("at least one --rules file is required"))
	}

	eng, err := engine.New(engine.Config{
		RulePaths: paths, ChunkSize: *chunk,
		MaxCacheBytes: *maxCache, VerifyLen: *verifyLen,
	})
	if err != nil {
		fatal(err)
	}
	set := eng.Rules()

	if *reload {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(set)
		return
	}

	targets := flag.Args()
	if len(targets) == 0 {
		fatal(fmt.Errorf("at least one file to scan is required"))
	}

	results := eng.ScanBatch(targets)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fatal(err)
	}

	if !*quiet {
		for _, r := range results {
			fmt.Fprintf(os.Stderr,
				"sigscan: rule_set_version=%s file_id=%s status=%s mode=%s read=%d processed=%d reused=%d size=%d verify_read=%d probe=%s hits=%d duration_ms=%d\n",
				r.RuleVersion, r.FileID, r.Status, r.Stats.Mode,
				r.Stats.BytesRead, r.Stats.BytesProcessed, r.Stats.BytesReused,
				r.Stats.FileSize, r.Stats.VerifyBytesRead, r.Stats.ResumeProbe,
				len(r.Hits), r.Stats.DurationMS)
		}
	}

	for _, r := range results {
		if !r.Status.IsOK() {
			os.Exit(2)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "sigscan:", err)
	os.Exit(1)
}
