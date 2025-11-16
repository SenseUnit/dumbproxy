package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"time"

	xproxy "golang.org/x/net/proxy"
)

type CommandDialer struct {
	command   []string
	waitDelay time.Duration
}

func CommandDialerFromURL(u *url.URL, _ xproxy.Dialer) (xproxy.Dialer, error) {
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, err
	}
	cmd := params.Get("cmd")
	if cmd == "" {
		return nil, errors.New("command is not specified")
	}
	args := params["arg"]
	waitDelay := 5 * time.Second
	if wd := params.Get("wait_delay"); wd != "" {
		waitDelay, err = time.ParseDuration(wd)
		if err != nil {
			return nil, fmt.Errorf("unable to parse wait_delay parameter: %w", err)
		}
	}
	command := make([]string, 0, len(args)+1)
	command = append(command, cmd)
	command = append(command, args...)
	return &CommandDialer{
		command:   command,
		waitDelay: waitDelay,
	}, nil
}

func (d *CommandDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *CommandDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	cmd := exec.CommandContext(ctx, d.command[0], d.command[1:]...)
	cmd.Env = append(os.Environ(),
		"DUMBPROXY_DST_ADDR="+address,
		"DUMBPROXY_DST_NET="+network,
	)
	cmdIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("can't create stdin pipe for subprocess: %w", err)
	}
	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("can't create stdout pipe for subprocess: %w", err)
	}
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = d.waitDelay
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("unable to start subprocess: %w", err)
	}
	go func() {
		cmd.Wait()
		cmdIn.Close()
		cmdOut.Close()
	}()
	return NewPipeConn(cmdOut.(ReadPipe), cmdIn.(WritePipe)), nil
}

func (d *CommandDialer) WantsHostname(_ context.Context, _, _ string) bool {
	return true
}

var _ Dialer = new(CommandDialer)
var _ HostnameWanter = new(CommandDialer)
