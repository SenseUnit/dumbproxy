package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/SenseUnit/dumbproxy/auth"
	"github.com/SenseUnit/dumbproxy/tlsutil"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

func version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	return bi.Main.Version
}

func hmacGenKey(args ...string) error {
	buf := make([]byte, auth.HMACSignatureSize)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("CSPRNG failure: %w", err)
	}
	fmt.Println(hex.EncodeToString(buf))
	return nil
}

func hmacSign(args ...string) error {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "dumbproxy -hmac-sign <HMAC key> <username> <validity duration>")
		fmt.Fprintln(os.Stderr, "")
		return errors.New("bad command line arguments")
	}

	secret, err := hex.DecodeString(args[0])
	if err != nil {
		return fmt.Errorf("unable to hex-decode HMAC secret: %w", err)
	}

	validity, err := time.ParseDuration(args[2])
	if err != nil {
		return fmt.Errorf("unable to parse validity duration: %w", err)
	}

	expire := time.Now().Add(validity).Unix()
	mac := auth.CalculateHMACSignature(secret, args[1], expire)
	token := auth.HMACToken{
		Expire: expire,
	}
	copy(token.Signature[:], mac)

	var resBuf bytes.Buffer
	enc := base64.NewEncoder(base64.RawURLEncoding, &resBuf)
	if err := binary.Write(enc, binary.BigEndian, &token); err != nil {
		return fmt.Errorf("token encoding failed: %w", err)
	}
	enc.Close()

	fmt.Println("Username:", args[1])
	fmt.Println("Password:", resBuf.String())
	return nil
}

func list_ciphers() {
	for _, cipher := range tls.CipherSuites() {
		fmt.Println(cipher.Name)
	}
}

func list_curves() {
	for _, curve := range tlsutil.Curves() {
		fmt.Println(curve.String())
	}
}

func passwd(filename string, cost int, args ...string) error {
	var (
		username, password, password2 string
		err                           error
	)

	if len(args) > 0 {
		username = args[0]
	} else {
		username, err = prompt("Enter username: ", false)
		if err != nil {
			return fmt.Errorf("can't get username: %w", err)
		}
	}

	if len(args) > 1 {
		password = args[1]
	} else {
		password, err = prompt("Enter password: ", true)
		if err != nil {
			return fmt.Errorf("can't get password: %w", err)
		}
		password2, err = prompt("Repeat password: ", true)
		if err != nil {
			return fmt.Errorf("can't get password (repeat): %w", err)
		}
		if password != password2 {
			return fmt.Errorf("passwords do not match")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return fmt.Errorf("can't generate password hash: %w", err)
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("can't open file: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(fmt.Sprintf("%s:%s\n", username, hash))
	if err != nil {
		return fmt.Errorf("can't write to file: %w", err)
	}

	return nil
}

func prompt(prompt string, secure bool) (string, error) {
	var input string
	fmt.Print(prompt)

	if secure {
		b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		input = string(b)
		fmt.Println()
	} else {
		fmt.Scanln(&input)
	}
	return input, nil
}
