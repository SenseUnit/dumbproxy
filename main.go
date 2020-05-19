package main

import (
    "log"
    "os"
    "fmt"
    "flag"
    "time"
    "net/http"
)

func perror(msg string) {
    fmt.Fprintln(os.Stderr, "")
    fmt.Fprintln(os.Stderr, msg)
}

func arg_fail(msg string) {
    perror(msg)
    perror("Usage:")
    flag.PrintDefaults()
    os.Exit(2)
}

type CLIArgs struct {
    bind_address string
    verbosity int
    timeout time.Duration
}


func parse_args() CLIArgs {
    var args CLIArgs
    flag.StringVar(&args.bind_address, "bind-address", ":8080", "HTTP proxy listen address")
    flag.IntVar(&args.verbosity, "verbosity", 20, "logging verbosity " +
            "(10 - debug, 20 - info, 30 - warning, 40 - error, 50 - critical)")
    flag.DurationVar(&args.timeout, "timeout", 10 * time.Second, "timeout for network operations")
    flag.Parse()
    return args
}

func run() int {
    args := parse_args()

    logWriter := NewLogWriter(os.Stderr)
    defer logWriter.Close()

    mainLogger := NewCondLogger(log.New(logWriter, "MAIN    : ",
                                log.LstdFlags | log.Lshortfile),
                                args.verbosity)
    proxyLogger := NewCondLogger(log.New(logWriter, "PROXY   : ",
                                log.LstdFlags | log.Lshortfile),
                                args.verbosity)
    mainLogger.Info("Starting proxy server...")
    handler := NewProxyHandler(proxyLogger)
    err := http.ListenAndServe(args.bind_address, handler)
    mainLogger.Critical("Server terminated with a reason: %v", err)
    mainLogger.Info("Shutting down...")
    return 0
}

func main() {
    os.Exit(run())
}
