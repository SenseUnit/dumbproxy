package jsext

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dop251/goja"
)

func parseWD(s string) (time.Weekday, error) {
	switch s {
	case "SUN":
		return time.Sunday, nil
	case "MON":
		return time.Monday, nil
	case "TUE":
		return time.Tuesday, nil
	case "WED":
		return time.Wednesday, nil
	case "THU":
		return time.Thursday, nil
	case "FRI":
		return time.Friday, nil
	case "SAT":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("unable to parse week day name: %q", s)
	}
}

func parseMonth(s string) (time.Month, error) {
	switch s {
	case "JAN":
		return time.January, nil
	case "FEB":
		return time.February, nil
	case "MAR":
		return time.March, nil
	case "APR":
		return time.April, nil
	case "MAY":
		return time.May, nil
	case "JUN":
		return time.June, nil
	case "JUL":
		return time.July, nil
	case "AUG":
		return time.August, nil
	case "SEP":
		return time.September, nil
	case "OCT":
		return time.October, nil
	case "NOV":
		return time.November, nil
	case "DEC":
		return time.December, nil
	default:
		return 0, fmt.Errorf("unable to parse month name: %q", s)
	}
}

func wdRange(vm *goja.Runtime, a, b string, gmt bool) goja.Value {
	a = strings.ToUpper(a)
	b = strings.ToUpper(b)
	an, err := parseWD(a)
	if err != nil {
		panic(vm.NewGoError(err))
	}
	bn, err := parseWD(b)
	if err != nil {
		panic(vm.NewGoError(err))
	}
	if an > bn {
		an, bn = bn, an
	}
	t := time.Now()
	if gmt {
		t = t.UTC()
	}
	wd := t.Weekday()
	return vm.ToValue(wd >= an && wd <= bn)
}

func AddWeekdayRange(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("weekdayRange", func(call goja.FunctionCall) goja.Value {
		switch len(call.Arguments) {
		case 0:
			panic(vm.NewTypeError("weekdayRange expects at least one argument"))
		case 1:
			return wdRange(vm, call.Argument(0).String(), call.Argument(0).String(), false)
		case 2:
			if strings.ToUpper(call.Argument(1).String()) == "GMT" {
				return wdRange(vm, call.Argument(0).String(), call.Argument(0).String(), true)
			} else {
				return wdRange(vm, call.Argument(0).String(), call.Argument(1).String(), false)
			}
		default:
			if strings.ToUpper(call.Argument(2).String()) == "GMT" {
				return wdRange(vm, call.Argument(0).String(), call.Argument(1).String(), true)
			} else {
				return wdRange(vm, call.Argument(0).String(), call.Argument(1).String(), false)
			}
		}
	})
}

func dateRange(params ...string) bool {
	now := time.Now()
	if strings.ToUpper(params[len(params)-1]) == "GMT" {
		now = now.UTC()
		params = params[:len(params)-1] // Strip the GMT flag
	}

	currentDay := now.Day()
	currentMonth := now.Month()
	currentYear := now.Year()

	isYear := func(s string) bool {
		val, err := strconv.Atoi(s)
		return err == nil && val > 31
	}
	isDay := func(s string) bool {
		val, err := strconv.Atoi(s)
		return err == nil && val >= 1 && val <= 31
	}

	switch len(params) {
	case 1:
		// Single parameter: True if current day/month/year matches it exactly
		val := params[0]
		if isYear(val) {
			y, _ := strconv.Atoi(val)
			return currentYear == y
		}
		if m, err := parseMonth(val); err == nil {
			return currentMonth == m
		}
		if isDay(val) {
			d, _ := strconv.Atoi(val)
			return currentDay == d
		}

	case 2:
		// Two parameters: Can be (day1, day2), (month1, month2), or (year1, year2)
		p1, p2 := params[0], params[1]
		if isYear(p1) && isYear(p2) {
			y1, _ := strconv.Atoi(p1)
			y2, _ := strconv.Atoi(p2)
			return currentYear >= y1 && currentYear <= y2
		}
		m1, err1 := parseMonth(p1)
		m2, err2 := parseMonth(p2)
		if err1 == nil && err2 == nil {
			return currentMonth >= m1 && currentMonth <= m2
		}
		if isDay(p1) && isDay(p2) {
			d1, _ := strconv.Atoi(p1)
			d2, _ := strconv.Atoi(p2)
			return currentDay >= d1 && currentDay <= d2
		}

	case 4:
		// Four parameters: Can be (day1, month1, day2, month2) or (month1, year1, month2, year2)
		m1, err1 := parseMonth(params[0])
		m2, err2 := parseMonth(params[2])
		if err1 == nil && err2 == nil { // (month1, year1, month2, year2)
			y1, _ := strconv.Atoi(params[1])
			y2, _ := strconv.Atoi(params[3])

			start := time.Date(y1, m1, 1, 0, 0, 0, 0, now.Location())
			// End of the month
			end := time.Date(y2, m2+1, 1, 0, 0, 0, 0, now.Location()).Add(-1)
			return (now.After(start) || now.Equal(start)) && (now.Before(end) || now.Equal(end))
		} else { // (day1, month1, day2, month2)
			d1, _ := strconv.Atoi(params[0])
			m1, _ := parseMonth(params[1])
			d2, _ := strconv.Atoi(params[2])
			m2, _ := parseMonth(params[3])

			start := time.Date(currentYear, m1, d1, 0, 0, 0, 0, now.Location())
			end := time.Date(currentYear, m2, d2, 23, 59, 59, 0, now.Location())
			return (now.After(start) || now.Equal(start)) && (now.Before(end) || now.Equal(end))
		}
	case 6:
		// Six parameters: (day1, month1, year1, day2, month2, year2)
		d1, _ := strconv.Atoi(params[0])
		m1, _ := parseMonth(params[1])
		y1, _ := strconv.Atoi(params[2])
		d2, _ := strconv.Atoi(params[3])
		m2, _ := parseMonth(params[4])
		y2, _ := strconv.Atoi(params[5])

		start := time.Date(y1, m1, d1, 0, 0, 0, 0, now.Location())
		end := time.Date(y2, m2, d2, 23, 59, 59, 0, now.Location())
		return (now.After(start) || now.Equal(start)) && (now.Before(end) || now.Equal(end))
	}
	return false
}

func mapSlice[Slice ~[]FromT, FromT any, ToT any](s Slice, fn func(FromT) ToT) []ToT {
	if s == nil {
		return nil
	}
	res := make([]ToT, 0, len(s))
	for _, v := range s {
		res = append(res, fn(v))
	}
	return res
}

func AddDateRange(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("dateRange", func(call goja.FunctionCall) goja.Value {
		return vm.ToValue(dateRange(mapSlice(call.Arguments, func(v goja.Value) string { return v.String() })...))
	})
}

func timeRange(gmt bool, args ...int) bool {
	now := time.Now()
	if gmt {
		now = now.UTC()
	}
	curHour := now.Hour()
	curMin := now.Minute()
	curSec := now.Second()
	switch len(args) {
	case 1:
		return curHour == args[0]
	case 2:
		return curHour >= args[0] && curHour <= args[1]
	case 4:
		h1, m1 := args[0], args[1]
		h2, m2 := args[2], args[3]
		curTotalMin := (curHour * 60) + curMin
		startTotalMin := (h1 * 60) + m1
		endTotalMin := (h2 * 60) + m2
		return curTotalMin >= startTotalMin && curTotalMin <= endTotalMin
	case 6:
		h1, m1, s1 := args[0], args[1], args[2]
		h2, m2, s2 := args[3], args[4], args[5]
		curTotalSec := (curHour * 3600) + (curMin * 60) + curSec
		startTotalSec := (h1 * 3600) + (m1 * 60) + s1
		endTotalSec := (h2 * 3600) + (m2 * 60) + s2
		return curTotalSec >= startTotalSec && curTotalSec <= endTotalSec
	}
	return false
}

func AddTimeRange(vm *goja.Runtime) error {
	return vm.GlobalObject().Set("timeRange", func(call goja.FunctionCall) goja.Value {
		args := call.Arguments
		if len(args) == 0 {
			return vm.ToValue(false)
		}
		gmt := false
		if strings.ToUpper(args[len(args)-1].String()) == "GMT" {
			gmt = true
			args = args[:len(args)-1]
		}
		return vm.ToValue(
			timeRange(
				gmt,
				mapSlice(args, func(v goja.Value) int { return int(v.ToInteger()) })...,
			),
		)
	})
}
