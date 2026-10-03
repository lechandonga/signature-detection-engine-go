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
	cacheBytes := flag.Int64("cache-bytes", 0, "bounded cache/resume-progress capacity in accounted bytes (0 = unlimited)")
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

	eng, err := engine.New(engine.Config{RulePaths: paths, ChunkSize: *chunk, CacheLimitBytes: *cacheBytes})
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

	for _, r := range results {
		fmt.Fprintf(os.Stderr,
			"sigscan: version=%s file=%s status=%s mode=%s progress=%s hits=%d "+
				"bytes_read=%d bytes_processed=%d bytes_reused=%d bytes_verified=%d "+
				"cache_entries=%d cache_cost=%d cache_limit=%d cache_evictions=%d\n",
			r.RuleVersion, r.FileID, r.Status, r.Mode, r.Progress, len(r.Hits),
			r.Work.BytesRead, r.Work.BytesProcessed, r.Work.BytesReused, r.Work.BytesVerified,
			r.Work.CacheEntries, r.Work.CacheCostBytes, r.Work.CacheLimitBytes, r.Work.CacheEvictions)
	}

	for _, r := range results {
		if r.Status != engine.StatusOK {
			os.Exit(2)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "sigscan:", err)
	os.Exit(1)
}
