// Command score evaluates one or more hostnames against 47-day TLS readiness
// checks and prints a 0-100 score.
//
// Usage:
//
//	score [flags] host [host ...]
//
// Exit codes: 0 ok, 1 findings below fail-under, 2 usage/error.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tigertrust/47-day-readiness-score/internal/scorer"
)

const usage = `score — TigerTrust 47-day TLS certificate readiness

Usage:
  score [flags] host [host ...]

Examples:
  # Score a single host (human-readable output)
  score example.com

  # Score several hosts and emit JSON
  score --json api.example.com www.example.com

  # Score on a non-standard port with a longer timeout
  score --port 8443 --timeout 30s internal-api.example.com

  # Write a markdown report to a file
  score --markdown report.md tigertrust.io

  # CI gate: exit 1 if any host scores below 80
  score --fail-under 80 api.example.com www.example.com

Exit codes:
  0  all hosts scored >= --fail-under (or --fail-under was 0)
  1  at least one host scored below --fail-under
  2  usage / invocation error

Flags:
`

func main() {
	fs := flag.NewFlagSet("score", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}

	port := fs.Int("port", 443, "TCP port to connect to")
	timeout := fs.Duration("timeout", 10*time.Second, "overall TLS/HTTP/DNS timeout")
	jsonOut := fs.Bool("json", false, "emit JSON")
	mdOut := fs.String("markdown", "", "write GitHub-flavored markdown report to this file")
	failUnder := fs.Int("fail-under", 0, "exit 1 if any host scores below this value")
	insecure := fs.Bool("insecure-skip-verify", false, "do not verify server certificate (lab only)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	hosts := fs.Args()
	if len(hosts) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	opts := scorer.DefaultOptions()
	opts.Port = *port
	opts.Timeout = *timeout
	opts.InsecureSkipVerify = *insecure

	reports := make([]*scorer.Report, 0, len(hosts))
	worstBelow := false
	for _, h := range hosts {
		r := scorer.Score(h, opts)
		reports = append(reports, r)
		if *failUnder > 0 && r.Score < *failUnder {
			worstBelow = true
		}
	}

	switch {
	case *jsonOut:
		for _, r := range reports {
			if err := r.WriteJSON(os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "json:", err)
				os.Exit(2)
			}
		}
	default:
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(os.Stdout)
			}
			r.WriteText(os.Stdout)
		}
	}

	if *mdOut != "" {
		f, err := os.Create(*mdOut)
		if err != nil {
			fmt.Fprintln(os.Stderr, "markdown:", err)
			os.Exit(2)
		}
		for i, r := range reports {
			if i > 0 {
				fmt.Fprintln(f)
			}
			r.WriteMarkdown(f)
		}
		f.Close()
	}

	if worstBelow {
		os.Exit(1)
	}
}
