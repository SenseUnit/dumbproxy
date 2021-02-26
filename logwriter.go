package main

import (
	"errors"
	"io"
	"time"
)

const MAX_LOG_QLEN = 128
const QUEUE_SHUTDOWN_TIMEOUT = 500 * time.Millisecond

type LogWriter struct {
	writer io.Writer
	ch     chan []byte
	done   chan struct{}
}

func (lw *LogWriter) Write(p []byte) (int, error) {
	if p == nil {
		return 0, errors.New("Can't write nil byte slice")
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

func NewLogWriter(writer io.Writer) *LogWriter {
	lw := &LogWriter{writer,
		make(chan []byte, MAX_LOG_QLEN),
		make(chan struct{})}
	go lw.loop()
	return lw
}

func (lw *LogWriter) loop() {
	for p := range lw.ch {
		if p == nil {
			break
		}
		lw.writer.Write(p)
	}
	lw.done <- struct{}{}
}

func (lw *LogWriter) Close() {
	lw.ch <- nil
	timer := time.After(QUEUE_SHUTDOWN_TIMEOUT)
	select {
	case <-timer:
	case <-lw.done:
	}
}
