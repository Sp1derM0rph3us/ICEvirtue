package scheduler

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/robfig/cron/v3"
)

// cronParser must accept exactly what the scheduler's cron instance accepts. NewScheduler
// builds it with cron.WithSeconds, which is the six-field dialect plus descriptors like
// @every.
var cronParser = cron.NewParser(
	cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
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

	expr := input
	switch {
	case dailyRegex.MatchString(input):
		m := dailyRegex.FindStringSubmatch(input)
		// cron/v3 with WithSeconds expects: Seconds Minutes Hours DayOfMonth Month DayOfWeek
		expr = fmt.Sprintf("0 %s %s * * *", m[2], m[1])
	case weeklyRegex.MatchString(input):
		m := weeklyRegex.FindStringSubmatch(input)
		// Defaults to Sunday (0) at HH:MM
		expr = fmt.Sprintf("0 %s %s * * 0", m[2], m[1])
	case monthRegex.MatchString(input):
		m := monthRegex.FindStringSubmatch(input)
		// Defaults to the 1st of the month at HH:MM
		expr = fmt.Sprintf("0 %s %s 1 * *", m[2], m[1])
	case yearRegex.MatchString(input):
		m := yearRegex.FindStringSubmatch(input)
		// Defaults to Jan 1st at HH:MM
		expr = fmt.Sprintf("0 %s %s 1 1 *", m[2], m[1])
	}

	// Everything goes through the parser, including the expressions built above.
	//
	// Two separate problems this closes. A raw expression used to be accepted on a field
	// count alone, so "whenever I feel like it" — five words — was stored as a schedule.
	// And the human-readable forms were returned unvalidated, so "every day at 99:99"
	// matched the regex and produced "0 99 99 * * *". In both cases the failure surfaced
	// later inside Sync, where it is logged and the profile is skipped, so the API answered
	// 200 for a profile that would never fire and nothing on screen said so.
	//
	// Note the field count: because the scheduler is built with cron.WithSeconds, a valid
	// raw expression needs six fields rather than the usual five. Delegating to the same
	// parser is what makes that rule true here and not only at schedule time.
	if _, err := cronParser.Parse(expr); err != nil {
		return "", fmt.Errorf("invalid schedule %q: %w. Supported formats: '@every 12h', "+
			"'every day at 14:30', 'every week at 00:00', or a six-field cron expression "+
			"(seconds minutes hours day-of-month month day-of-week)", input, err)
	}
	return expr, nil
}
