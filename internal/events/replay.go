package events

import (
	"bytes"
	"context"

	"github.com/Parsa-Emami/Miragemesh/internal/contracts"
)

func (w *Writer) Read(ctx context.Context, ref Entry) ([]byte, error) {
	if w == nil {
		return nil, ErrInvalidInput
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.available(ctx); err != nil {
		return nil, err
	}
	indexed, ok := w.indexEntry(ref.SensorID, ref.EventID)
	if !ok || indexed != ref {
		return nil, ErrIndexConflict
	}
	for _, segment := range w.segments {
		if segment.id != ref.Segment {
			continue
		}
		data, err := w.readFile(segment.name, w.limits.MaxBytesPerSegment)
		if err != nil {
			return nil, err
		}
		var record int64
		for len(data) > 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			end := bytes.IndexByte(data, '\n')
			if end < 0 {
				break
			}
			record++
			if record == ref.Record {
				payload, err := decodeFrame(data[:end])
				if err != nil {
					return nil, err
				}
				event, failure := contracts.DecodeEvent(ctx, payload)
				if failure != nil || digest(payload) != ref.Digest || int64(len(payload)) != ref.Bytes || event.SensorID != ref.SensorID || event.EventID != ref.EventID || event.Sequence != ref.Sequence {
					return nil, ErrIndexConflict
				}
				return append([]byte(nil), payload...), nil
			}
			data = data[end+1:]
		}
		return nil, ErrRecovery
	}
	return nil, ErrRecovery
}
