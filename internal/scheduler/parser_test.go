package scheduler

import (
	"testing"
)

func TestParseSchedule(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "Daily",
			input:    "every day at 14:30",
			expected: "0 30 14 * * *",
			wantErr:  false,
		},
		{
			name:     "Daily Case Insensitive",
			input:    "EVERY DAY AT 09:05",
			expected: "0 05 09 * * *",
			wantErr:  false,
		},
		{
			name:     "Weekly",
			input:    "every week at 12:00",
			expected: "0 00 12 * * 0",
			wantErr:  false,
		},
		{
			name:     "Weekly Case Insensitive",
			input:    "EveRy weeK at 23:59",
			expected: "0 59 23 * * 0",
			wantErr:  false,
		},
		{
			name:     "Monthly",
			input:    "every month at 10:00",
			expected: "0 00 10 1 * *",
			wantErr:  false,
		},
		{
			name:     "Yearly",
			input:    "every year at 00:00",
			expected: "0 00 00 1 1 *",
			wantErr:  false,
		},
		{
			name:     "Standard @every",
			input:    "@every 12h",
			expected: "@every 12h",
			wantErr:  false,
		},
		{
			name:     "Standard Cron Expression",
			input:    "0 30 14 * * *",
			expected: "0 30 14 * * *",
			wantErr:  false,
		},
		{
			name:     "Invalid Format",
			input:    "every decade at 12:00",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "Invalid Daily Format",
			input:    "everyday at 14:30",
			expected: "",
			wantErr:  true,
		},
		{
			name:     "Invalid Time Format",
			input:    "every day at 1430",
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSchedule(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSchedule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseSchedule() got = %v, expected %v", got, tt.expected)
			}
		})
	}
}
