package native

import "errors"

// HandoffServer is the exported fd-handoff server (see
// StartHandoffServer / ReceiveHandoff in handoff.go).
type HandoffServer = handoffServer

// FilterELFBytes returns the embedded XDP filter object handed to
// loading backends (native in-process, or external loaders such as
// bpfman via a File bytecode location).
func FilterELFBytes() ([]byte, error) {
	if len(_FilterBytes) == 0 {
		return nil, errors.New("filter ELF not embedded")
	}
	return append([]byte(nil), _FilterBytes...), nil
}
