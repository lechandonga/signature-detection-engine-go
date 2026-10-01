// Command sigscan loads local signature rules and scans local files. It never
// contacts any external service.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/lechandonga/signature-detection-engine-go/internal/engine"
	"github.com/lechandonga/signature-detection-engine-go/internal/rules"
)

func main() {
	log.SetFlags(log.LstdFlags)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "compile":
		cmdCompile(os.Args[2:])
	case "scan":
		cmdScan(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sigscan - local file signature detection engine

Usage:
  sigscan compile --rules <dir>
      Load rule files, print the rule-set version and per-file rejections.

  sigscan scan --rules <dir> [--chunk <bytes>] [--workers <n>] [--json] <file>...
      Scan files against the current rule set. One file's failure is reported
      individually and never interrupts the others.
`)
}

func ruleDirFlag(fs *flag.FlagSet) *string {
	return fs.String("rules", "rules", "directory containing *.json rule files")
}

func cmdCompile(args []string) {
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	rulesDir := ruleDirFlag(fs)
	_ = fs.Parse(args)

	store := rules.NewStore()
	version, rejected := store.Reload(*rulesDir)
	snap := store.Snapshot()
	fmt.Printf("rule_set_version: %s\n", version)
	fmt.Printf("active_rules: %d\n", len(snap.Rules))
	for _, rj := range rejected {
		fmt.Printf("rejected: %s\n", rj.Error())
	}
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	rulesDir := ruleDirFlag(fs)
	chunk := fs.Int("chunk", 64*1024, "streaming chunk size in bytes")
	workers := fs.Int("workers", 4, "concurrent scan workers")
	asJSON := fs.Bool("json", false, "emit one JSON result per file on stdout")
	_ = fs.Parse(args)

	paths := fs.Args()
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "scan: at least one file is required")
		os.Exit(2)
	}

	store := rules.NewStore()
	version, rejected := store.Reload(*rulesDir)
	for _, rj := range rejected {
		log.Printf("rule rejection: %s", rj.Error())
	}
	log.Printf("loaded rule_set_version=%s active_rules=%d", version, len(store.Snapshot().Rules))

	eng := engine.New(store, engine.Config{ChunkSize: *chunk, Workers: *workers})
	results := eng.ScanBatch(paths)

	enc := json.NewEncoder(os.Stdout)
	exitOK := true
	for _, r := range results {
		if *asJSON {
			if err := enc.Encode(r); err != nil {
				log.Fatal(err)
			}
		} else {
			fmt.Printf("%-10s %s  rules=%s  hits=%d  cache_hit=%t",
				r.Status, r.FileID, r.RuleVer, len(r.Hits), r.CacheHit)
			if r.Error != "" {
				fmt.Printf("  error=%q", r.Error)
			}
			fmt.Println()
		}
		for _, h := range r.Hits {
			log.Printf("hit file_id=%s rule_set_version=%s rule_id=%s offset=%d mode=%s term_offsets=%v",
				r.FileID, r.RuleVer, h.RuleID, h.Offset, h.MatchMode, h.TermHits)
		}
		if r.Status != engine.StatusClean && r.Status != engine.StatusDetected {
			exitOK = false
		}
	}
	if !exitOK {
		os.Exit(1)
	}
}
