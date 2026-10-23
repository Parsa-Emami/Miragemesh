package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
	"github.com/Parsa-Emami/Miragemesh/internal/events"
)

type retentionOptions struct {
	Enabled   bool
	Apply     bool
	Directory string
	Before    string
	Reason    string
	Key       string
	Limits    events.Limits
}

func retentionFlags() *retentionOptions {
	options := new(retentionOptions)
	flag.BoolVar(&options.Enabled, "expire-segments", false, "plan expiration of complete sealed event segments and exit")
	flag.BoolVar(&options.Apply, "retention-apply", false, "apply the explicit retention decision and delete its sealed segments")
	flag.StringVar(&options.Directory, "retention-dir", "", "existing private event segment directory")
	flag.StringVar(&options.Before, "retention-before", "", "exclusive observed-at cutoff in RFC3339")
	flag.StringVar(&options.Reason, "retention-reason", "", "operator reason retained in the audit")
	flag.StringVar(&options.Key, "retention-key", "", "idempotency key of 16 to 128 characters")
	flag.IntVar(&options.Limits.MaxSegments, "retention-max-segments", 0, "explicit segment count limit")
	flag.Int64Var(&options.Limits.MaxRecordsPerSegment, "retention-max-records", 0, "explicit record limit per segment")
	flag.Int64Var(&options.Limits.MaxBytesPerSegment, "retention-max-bytes", 0, "explicit byte limit per segment")
	return options
}

func retentionConfigured() bool {
	configured := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "expire-segments" || strings.HasPrefix(f.Name, "retention-") {
			configured = true
		}
	})
	return configured
}

func runRetention(options *retentionOptions) int {
	type outcome struct {
		Scope         string                  `json:"scope"`
		Status        string                  `json:"status"`
		Result        *events.RetentionResult `json:"result,omitempty"`
		IndexKnown    bool                    `json:"index_known"`
		IndexRecords  int64                   `json:"index_records"`
		IndexComplete bool                    `json:"index_complete"`
		ErrorKind     string                  `json:"error_kind,omitempty"`
	}
	value := outcome{Scope: "event-retention", Status: "failed"}
	finish := func(err error) int {
		if err != nil {
			value.Status = "failed"
			value.ErrorKind = segmentProjectionErrorKind(err)
		}
		if json.NewEncoder(os.Stdout).Encode(value) != nil {
			return 1
		}
		if err == nil {
			return 0
		}
		if errors.Is(err, events.ErrInvalidInput) {
			return 2
		}
		return 1
	}
	mixed := flag.NArg() != 0
	flag.Visit(func(f *flag.Flag) {
		if f.Name != "expire-segments" && !strings.HasPrefix(f.Name, "retention-") {
			mixed = true
		}
	})
	before, err := time.Parse(time.RFC3339Nano, options.Before)
	if !options.Enabled || mixed || err != nil || options.Directory == "" || options.Reason == "" || options.Key == "" || options.Limits.MaxSegments <= 0 || options.Limits.MaxRecordsPerSegment <= 0 || options.Limits.MaxBytesPerSegment < contracts.MaxInputBytes+1 {
		return finish(events.ErrInvalidInput)
	}
	info, err := os.Lstat(options.Directory)
	if err != nil {
		return finish(events.ErrIO)
	}
	if !info.IsDir() {
		return finish(events.ErrInvalidInput)
	}
	w, err := events.Open(options.Directory, options.Limits)
	if err != nil {
		return finish(err)
	}
	request := events.RetentionRequest{Before: before, Reason: options.Reason, IdempotencyKey: options.Key}
	var result events.RetentionResult
	if options.Apply {
		result, err = w.Expire(context.Background(), request)
	} else {
		result, err = w.PlanRetention(context.Background(), request)
	}
	if err == nil {
		value.Result = &result
		value.Status = "planned"
		if options.Apply {
			value.Status = "applied"
		}
	}
	if index, indexErr := w.Index(); indexErr == nil {
		value.IndexKnown = true
		value.IndexRecords = index.Records
		value.IndexComplete = index.Complete
	}
	if closeErr := w.Close(); closeErr != nil {
		err = errors.Join(err, closeErr)
	}
	if err != nil && value.Result != nil {
		fmt.Fprintln(os.Stderr, "Retention committed but close failed; retry the same key after reopening")
	}
	return finish(err)
}
