package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fake(t *testing.T) {
	old := run
	t.Cleanup(func() { run = old })
	run = func(algo string, msg []byte) ([]byte, error) {
		n := 64
		if algo == "Streebog-256" {
			n = 32
		}
		return bytes.Repeat([]byte{0xab}, n), nil
	}
}

func TestGenerate(t *testing.T) {
	fake(t)
	out := filepath.Join(t.TempDir(), "v.vec")
	cmd := RootCmd()
	var so bytes.Buffer
	cmd.SetOut(&so)
	cmd.SetArgs([]string{"-n", "3", "-o", out})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if got := strings.Count(string(b), "\nIn = "); got != 6 {
		t.Fatalf("%d vectors, want 6", got)
	}
	if !strings.Contains(string(b), "[Streebog-256]") || !strings.Contains(string(b), "[Streebog-512]") {
		t.Fatal("missing section")
	}
	if !strings.Contains(so.String(), "wrote 3 vectors") {
		t.Fatal(so.String())
	}
	if !strings.Contains(string(b), "\nIn = \n") {
		t.Fatal("missing empty message")
	}
}

func TestLongLengths(t *testing.T) {
	fake(t)
	var buf bytes.Buffer
	if err := generate(&buf, 205); err != nil {
		t.Fatal(err)
	}
}

func TestErrors(t *testing.T) {
	old := run
	defer func() { run = old }()
	run = func(a string, b []byte) ([]byte, error) { return nil, errors.New("boom") }
	var buf bytes.Buffer
	if err := generate(&buf, 1); err == nil {
		t.Fatal("want error")
	}
	run = func(a string, b []byte) ([]byte, error) { return []byte{1}, nil }
	if err := generate(&buf, 1); err == nil {
		t.Fatal("want short-output error")
	}
}

func TestOutputUnwritable(t *testing.T) {
	fake(t)
	cmd := RootCmd()
	cmd.SetArgs([]string{"-n", "1", "-o", filepath.Join(t.TempDir(), "no", "such", "v.vec")})
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("want error")
	}
}

func TestMainExit(t *testing.T) {
	code := -1
	oldExit, oldArgs := osExit, os.Args
	osExit = func(c int) { code = c }
	defer func() { osExit, os.Args = oldExit, oldArgs }()
	os.Args = []string{"genbotan", "--bogus"}
	main()
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	os.Args = []string{"genbotan", "-n", "0", "-o", filepath.Join(t.TempDir(), "x")}
	code = -1
	main()
	if code != -1 {
		t.Fatalf("exit %d", code)
	}
}
