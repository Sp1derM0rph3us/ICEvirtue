package scheduler

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// Matches "every day at 14:30"
	dailyRegex = regexp.MustCompile(`(?i)^every day at (\d{1,2}):(\d{2})$`)
	// Matches "every week at 12:00"
	weeklyRegex = regexp.MustCompile(`(?i)^every week at (\d{1,2}):(\d{2})$`)
	// Matches "every month at 14:30"
	monthRegex = regexp.MustCompile(`(?i)^every month at (\d{1,2}):(\d{2})$`)
	// Matches "every year at 00:00"
	yearRegex = regexp.MustCompile(`(?i)^every year at (\d{1,2}):(\d{2})$`)
)

// ParseSchedule takes a user-provided schedule string and converts it to a cron expression compatible with cron/v3.
// Supported formats:
// - Standard cron expressions
// - @every {duration} (e.g., @every 12h)
// - "every day at HH:MM" (e.g., every day at 14:30)
// - "every week at HH:MM" (e.g., every week at 00:00)
func ParseSchedule(input string) (string, error) {
	input = strings.TrimSpace(input)

	// Direct pass-through for @every format
	if strings.HasPrefix(input, "@every ") {
		return input, nil
	}

	// Match "every day at HH:MM"
	if matches := dailyRegex.FindStringSubmatch(input); matches != nil {
		hour := matches[1]
		minute := matches[2]
		// cron/v3 with WithSeconds expects: Seconds Minutes Hours DayOfMonth Month DayOfWeek
		return fmt.Sprintf("0 %s %s * * *", minute, hour), nil
	}

	// Match "every week at HH:MM"
	if matches := weeklyRegex.FindStringSubmatch(input); matches != nil {
		hour := matches[1]
		minute := matches[2]
		// Defaults to Sunday (0) at HH:MM
		return fmt.Sprintf("0 %s %s * * 0", minute, hour), nil
	}

	// Match "every month at HH:MM"
	if matches := monthRegex.FindStringSubmatch(input); matches != nil {
		hour := matches[1]
		minute := matches[2]
		// Defaults to 1st of the month at HH:MM
		return fmt.Sprintf("0 %s %s 1 * *", minute, hour), nil
	}

	// Match "every year at HH:MM"
	if matches := yearRegex.FindStringSubmatch(input); matches != nil {
		hour := matches[1]
		minute := matches[2]
		// Defaults to Jan 1st at HH:MM
		return fmt.Sprintf("0 %s %s 1 1 *", minute, hour), nil
	}

	// Assume it's a standard cron expression (or other @ format) if it doesn't match the human-readable ones.
	// Basic validation (at least 5 fields or starts with @). cron/v3 parses it further.
	parts := strings.Fields(input)
	if len(parts) >= 5 || strings.HasPrefix(input, "@") {
		return input, nil
	}

	return "", fmt.Errorf("invalid schedule format: %s. Supported formats: '@every 12h', 'every day at 14:30', 'every week at 00:00', or standard cron expression", input)
}
