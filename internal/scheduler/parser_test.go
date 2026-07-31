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

// TestParseScheduleValidatesEveryForm covers the validation that ParseSchedule did not do.
//
// A raw expression used to be accepted on a field count alone — "whenever I feel like it"
// is five words — and the human-readable forms were returned without being parsed at all,
// so "every day at 99:99" produced "0 99 99 * * *". Both failures only surfaced later
// inside Sync, where they are logged and the profile is skipped, so the API answered 200
// for a schedule that would never fire.
func TestParseScheduleValidatesEveryForm(t *testing.T) {
	cases := []struct {
		input string
		valid bool
		note  string
	}{
		{"every day at 14:30", true, ""},
		{"every week at 00:00", true, ""},
		{"every month at 03:15", true, ""},
		{"every year at 12:00", true, ""},
		{"@every 12h", true, "descriptor"},
		{"@daily", true, "descriptor"},
		{"0 30 14 * * *", true, "six fields, as cron.WithSeconds requires"},

		{"whenever I feel like it", false, "five words is not a cron expression"},
		{"every day at 99:99", false, "the regex matches but the hour does not exist"},
		{"every day at 25:00", false, "hour out of range"},
		{"30 14 * * *", false, "five fields: valid standard cron, but this scheduler wants six"},
		{"@every banana", false, "not a duration"},
		{"", false, ""},
	}

	for _, c := range cases {
		_, err := ParseSchedule(c.input)
		if c.valid && err != nil {
			t.Errorf("ParseSchedule(%q) rejected a valid schedule: %v", c.input, err)
		}
		if !c.valid && err == nil {
			detail := c.note
			if detail == "" {
				detail = "it is not a valid schedule"
			}
			t.Errorf("ParseSchedule(%q) was accepted; %s", c.input, detail)
		}
	}
}
