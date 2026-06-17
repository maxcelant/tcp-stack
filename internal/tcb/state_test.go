package tcb

import "testing"

func TestStateString(t *testing.T) {
	tests := []struct {
		name  string
		state State
		want  string
	}{
		{"Listen", StateListen, "LISTEN"},
		{"Closed", StateClosed, "CLOSED"},
		{"FinWait1", StateFinWait1, "FIN-WAIT-1"},
		{"UnknownState", State(15), "State(15)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.state.String() != tt.want {
				t.Fatalf("%s=%s, want %s", tt.name, tt.state.String(), tt.want)
			}
		})
	}
}
