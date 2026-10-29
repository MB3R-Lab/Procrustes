package app

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/MB3R-Lab/Procrustes/internal/analyze"
	"github.com/MB3R-Lab/Procrustes/internal/config"
	"github.com/MB3R-Lab/Procrustes/internal/model"
	"github.com/MB3R-Lab/Procrustes/internal/output"
	"github.com/MB3R-Lab/Procrustes/internal/scan"
	"github.com/MB3R-Lab/Procrustes/internal/source"
)

type Runner struct {
	stdout io.Writer
	stderr io.Writer
}

func New(stdout, stderr io.Writer) *Runner { return &Runner{stdout: stdout, stderr: stderr} }

func (r *Runner) Run(args []string) int {
	if len(args) == 0 {
		r.usage()
		return 1
	}
	switch args[0] {
	case "analyze":
		return r.runAnalyze(args[1:])
	case "version", "--version", "-version":
		fmt.Fprintf(r.stdout, "procrustes %s\n", model.ToolVersion)
		return 0
	case "help", "--help", "-h":
		r.usage()
		return 0
	default:
		fmt.Fprintf(r.stderr, "unknown command %q\n", args[0])
		r.usage()
		return 1
	}
}

func (r *Runner) runAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(r.stderr)
	var sourceValues stringList
	fs.Var(&sourceValues, "source", "Static source in alias=path form; repeatable")
	goalPath := fs.String("goal", "", "Path to the Procrustes goal YAML")
	outDir := fs.String("out-dir", "", "Directory for report and handoff artifacts")
	collectionSource := fs.String("collection-source", "native", "Trace collection source: native, ebpf-obi, or ebpf-otlp")
	collector := fs.String("collector", "", "Declared collector name; required for ebpf-otlp")
	sourceDomain := fs.String("source-domain", "default", "eBPF collection deployment domain, shared by its agents")
	failOnBlocked := fs.Bool("fail-on-blocked", false, "Return exit code 2 when the selected capability is blocked")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if strings.TrimSpace(*goalPath) == "" || strings.TrimSpace(*outDir) == "" {
		fmt.Fprintln(r.stderr, "--goal and --out-dir are required")
		return 1
	}
	if err := analyze.ValidateCollectionProfile(*collectionSource, *collector, *sourceDomain); err != nil {
		fmt.Fprintf(r.stderr, "collection source: %v\n", err)
		return 1
	}
	sources, err := source.ParseSpecs(sourceValues)
	if err != nil {
		fmt.Fprintf(r.stderr, "source configuration: %v\n", err)
		return 1
	}
	goal, goalRaw, err := config.LoadGoal(*goalPath)
	if err != nil {
		fmt.Fprintf(r.stderr, "goal configuration: %v\n", err)
		return 1
	}
	files, err := source.ReadFiles(sources)
	if err != nil {
		fmt.Fprintf(r.stderr, "source scan: %v\n", err)
		return 1
	}
	if len(files) == 0 {
		fmt.Fprintln(r.stderr, "source scan: no YAML or JSON files found")
		return 1
	}
	report := analyze.Run(analyze.Input{
		Goal: goal, Sources: sources, Fingerprint: source.Fingerprint(goalRaw, files), Inventory: scan.Files(files),
		CollectionSource: *collectionSource, Collector: *collector, SourceDomain: *sourceDomain,
	})
	if err := output.Write(*outDir, report); err != nil {
		fmt.Fprintf(r.stderr, "write result: %v\n", err)
		return 1
	}
	fmt.Fprintf(r.stdout, "Procrustes goal: %s\n", report.GoalStatus)
	fmt.Fprintf(r.stdout, "Report written to %s\n", *outDir)
	if *failOnBlocked && report.GoalStatus == model.CapabilityBlocked {
		return 2
	}
	return 0
}

func (r *Runner) usage() {
	fmt.Fprintln(r.stderr, "Usage:")
	fmt.Fprintln(r.stderr, "  procrustes analyze --source <alias>=<path> [--source ...] --goal <goal.yaml> --out-dir <dir> [--collection-source native|ebpf-obi|ebpf-otlp] [--collector <name>] [--source-domain <deployment>] [--fail-on-blocked]")
	fmt.Fprintln(r.stderr, "  procrustes version")
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}
