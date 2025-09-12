package log

import (
	"context"
	"errors"
	"io"
)

type LogWriter struct {
	writer io.Writer
	ch     chan []byte
	done   chan struct{}
}

func (lw *LogWriter) Write(p []byte) (int, error) {
	if p == nil {
		return 0, nil
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case lw.ch <- buf:
		return len(p), nil
	default:
		return 0, errors.New("Writer queue overflow")
	}
}

func NewLogWriter(writer io.Writer, qlen int) *LogWriter {
	lw := &LogWriter{writer,
		make(chan []byte, qlen),
		make(chan struct{})}
	go lw.loop()
	return lw
}

func (lw *LogWriter) loop() {
	defer close(lw.done)
	for p := range lw.ch {
		if p == nil {
			break
		}
		lw.writer.Write(p)
	}
}

func (lw *LogWriter) Close(ctx context.Context) error {
	select {
	case lw.ch <- nil:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-lw.done:
			return nil
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-lw.done:
		return nil
	}
}
