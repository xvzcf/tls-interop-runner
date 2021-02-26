package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/xvzcf/tls-interop-runner/internal/pcap"
	"github.com/xvzcf/tls-interop-runner/internal/utils"
)

func waitWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-time.After(timeout):
		if err := cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill process:%s", err)
		}
		return errors.New("process timed out")
	case err := <-done:
		if err != nil {
			close(done)
			return err
		}
		return nil
	}
}

type testCase interface {
	setup() error
	run(client endpoint, server endpoint, verbose bool) error
	verify() error
}

type testError struct {
	err         string
	funcName    string
	unsupported bool
}

func (e *testError) Error() string {
	if e.unsupported {
		return fmt.Sprintf("Unsupported,%s(): %s", e.funcName, e.err)
	} else {
		return fmt.Sprintf("Failure,%s(): %s", e.funcName, e.err)
	}
}

type testCaseDC struct {
	name    string
	timeout time.Duration
}

func (t testCaseDC) setup() error {
	os.MkdirAll(testInputsDir, os.ModePerm)
	os.MkdirAll(testOutputsDir, os.ModePerm)

	var inputParams strings.Builder

	rootSignatureAlgorithm := utils.SignatureECDSAWithP521AndSHA512
	err := utils.MakeRootCertificate(
		&utils.Config{
			Hostnames:          []string{"root.com"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: rootSignatureAlgorithm,
		},
		path.Join(testInputsDir, "root.crt"),
		path.Join(testInputsDir, "root.key"),
	)
	if err != nil {
		return err
	}
	inputParams.WriteString(fmt.Sprintf("Root certificate algorithm: 0x%X\n", rootSignatureAlgorithm))

	intermediateSignatureAlgorithm := utils.SignatureECDSAWithP256AndSHA256
	err = utils.MakeIntermediateCertificate(
		&utils.Config{
			Hostnames:          []string{"example.com"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: intermediateSignatureAlgorithm,
			ForDC:              true,
		},
		path.Join(testInputsDir, "root.crt"),
		path.Join(testInputsDir, "root.key"),
		path.Join(testInputsDir, "example.crt"),
		path.Join(testInputsDir, "example.key"),
	)
	if err != nil {
		return err
	}
	inputParams.WriteString(fmt.Sprintf("Intermediate certificate algorithm: 0x%X\n", intermediateSignatureAlgorithm))

	dcAlgorithm := utils.SignatureECDSAWithP256AndSHA256
	dcValidFor := 24 * time.Hour
	err = utils.MakeDelegatedCredential(
		&utils.Config{
			ValidFor:           dcValidFor,
			SignatureAlgorithm: dcAlgorithm,
		},
		&utils.Config{},
		path.Join(testInputsDir, "example.crt"),
		path.Join(testInputsDir, "example.key"),
		path.Join(testInputsDir, "dc.txt"),
	)
	if err != nil {
		return err
	}
	inputParams.WriteString(fmt.Sprintf("Delegated credential algorithm: 0x%X\n", intermediateSignatureAlgorithm))
	inputParams.WriteString(fmt.Sprintf("DC valid for: %v\n", dcValidFor))

	inputParamsLog, err := os.Create(path.Join(testOutputsDir, "input-params.txt"))
	if err != nil {
		return err
	}
	defer inputParamsLog.Close()

	_, err = inputParamsLog.WriteString(inputParams.String())
	if err != nil {
		return err
	}

	return nil
}

func (t testCaseDC) run(client endpoint, server endpoint, verbose bool) error {
	cmd := exec.Command("docker-compose", "up", "-V", "--abort-on-container-exit")
	env := os.Environ()
	if server.regression {
		env = append(env, "SERVER_SRC=./regression-endpoints")
	} else {
		env = append(env, "SERVER_SRC=./impl-endpoints")
	}
	env = append(env, fmt.Sprintf("SERVER=%s", server.name))
	if client.regression {
		env = append(env, "CLIENT_SRC=./regression-endpoints")
	} else {
		env = append(env, "CLIENT_SRC=./impl-endpoints")
	}
	env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
	env = append(env, fmt.Sprintf("TESTCASE=%s", t.name))
	cmd.Env = env

	var cmdOut bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdOut

	err := cmd.Start()
	if err != nil {
		print(cmdOut.String())
		return &testError{err: fmt.Sprintf("docker-compose up start(): %s", err), funcName: "run"}
	}
	err = waitWithTimeout(cmd, t.timeout)
	if err != nil {
		print(cmdOut.String())
		if strings.Contains(err.Error(), "exit status 64") {
			return &testError{err: fmt.Sprintf("docker-compose up: %s", err), funcName: "run", unsupported: true}
		}
		return &testError{err: fmt.Sprintf("docker-compose up: %s", err), funcName: "run"}
	}
	if verbose {
		print(cmdOut.String())
	}
	runLog, err := os.Create(path.Join(testOutputsDir, "run.txt"))
	if err != nil {
		return &testError{err: fmt.Sprintf("os.Create failed: %s", err), funcName: "run"}
	}
	defer runLog.Close()
	w := bufio.NewWriter(runLog)
	_, err = cmdOut.WriteTo(w)
	if err != nil {
		return &testError{err: fmt.Sprintf("WriteTo failed: %s", err), funcName: "run"}
	}
	return nil
}

func (t testCaseDC) verify() error {
	err := pcap.FindTshark()
	if err != nil {
		return &testError{err: fmt.Sprintf("tshark not found: %s", err), funcName: "verify"}
	}

	pcapPath := path.Join("generated", "test-outputs", "client_node_trace.pcap")
	keylogPath := path.Join("generated", "test-outputs", "client_keylog")
	transcript, err := pcap.Parse(pcapPath, keylogPath)
	if err != nil {
		return &testError{err: fmt.Sprintf("could not parse pcap: %s", err), funcName: "verify"}
	}

	err = pcap.Validate(transcript, t.name)
	if err != nil {
		return &testError{err: fmt.Sprintf("could not validate pcap: %s", err), funcName: "verify"}
	}
	return nil
}

var testCases = map[string]testCase{
	"dc": testCaseDC{name: "dc", timeout: 100 * time.Second},
}
