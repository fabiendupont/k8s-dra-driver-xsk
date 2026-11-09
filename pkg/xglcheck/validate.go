package xglcheck

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Finding is one validation finding reported by xgl_check.
type Finding struct {
	Severity string // "ERROR" or "WARN"
	Code     string // e.g. "E_QUEUE_DUP"
	Message  string
}

// IsError reports whether the finding is error-severity.
func (f Finding) IsError() bool {
	return f.Severity == "ERROR"
}

// String renders the finding as the CLI does.
func (f Finding) String() string {
	return fmt.Sprintf("%s %s: %s", f.Severity, f.Code, f.Message)
}

// Validate runs the xgl_check binary on the spec.
//
// bin is the path to the xgl_check executable. It returns the
// findings (errors and warnings); a non-nil error is returned only
// if the check could not run at all (missing binary, parse failure).
// An empty findings slice means the spec is clean.
func Validate(spec *Spec, bin string) ([]Finding, error) {
	rendered, err := spec.Render()
	if err != nil {
		return nil, fmt.Errorf("rendering spec: %w", err)
	}

	tmp, err := os.CreateTemp("", "xgl-spec-*.xgl")
	if err != nil {
		return nil, fmt.Errorf("creating temp spec: %w", err)
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.WriteString(rendered); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing spec: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("closing spec: %w", err)
	}

	cmd := exec.Command(bin, tmp.Name())
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return nil, fmt.Errorf("running %s: %w", bin, err)
		}
		// exit 1 = validation errors, expected
	}

	var findings []Finding
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "ERROR ") && !strings.HasPrefix(line, "WARN ") {
			continue // summary lines, blank lines
		}
		f, perr := parseFinding(line)
		if perr != nil {
			return nil, fmt.Errorf("parsing xgl_check output %q: %w", line, perr)
		}
		findings = append(findings, f)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading xgl_check output: %w", err)
	}
	return findings, nil
}

// HasErrors reports whether any finding is error-severity.
func HasErrors(findings []Finding) bool {
	for _, f := range findings {
		if f.IsError() {
			return true
		}
	}
	return false
}

func parseFinding(line string) (Finding, error) {
	// "ERROR E_QUEUE_DUP: queue 'eth0:0' has more than one consumer"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return Finding{}, fmt.Errorf("malformed line")
	}
	severity, code := parts[0], parts[1]
	msg := strings.TrimPrefix(parts[2], ": ")
	if !strings.HasSuffix(code, ":") {
		return Finding{}, fmt.Errorf("malformed code field %q", code)
	}
	return Finding{
		Severity: severity,
		Code:     strings.TrimSuffix(code, ":"),
		Message:  msg,
	}, nil
}
