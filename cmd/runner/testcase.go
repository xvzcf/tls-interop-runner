// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/xvzcf/tls-interop-runner/internal/pcap"
	"github.com/xvzcf/tls-interop-runner/internal/utils"
)

type errorWithFnName struct {
	err    string
	fnName string
}

func (e *errorWithFnName) Error() string {
	return fmt.Sprintf("%s(): %s", e.fnName, e.err)
}

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

type resultType uint

const (
	resultError       resultType = iota
	resultFailure     resultType = iota
	resultSuccess     resultType = iota
	resultUnsupported resultType = iota
)

func (rt resultType) String() string {
	switch rt {
	case resultError:
		return "Error"
	case resultFailure:
		return "Failure"
	case resultSuccess:
		return "Success"
	case resultUnsupported:
		return "Skipped"
	default:
		return ""
	}
}

type testcase interface {
	setup(verbose bool) error
	run(client endpoint, server endpoint) (resultType, error)
	verify() (resultType, error)
	teardown(moveOutputs bool) error
}

type testcaseDC struct {
	name      string
	timeout   time.Duration
	outputDir string
	logger    *log.Logger
	logFile   *os.File
}

func (t *testcaseDC) setup(verbose bool) error {
	err := os.RemoveAll(testInputsDir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(testInputsDir, os.ModePerm)
	if err != nil {
		return err
	}

	err = os.RemoveAll(testOutputsDir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(testOutputsDir, os.ModePerm)
	if err != nil {
		return err
	}
	runLog, err := os.Create(filepath.Join(testOutputsDir, "run-log.txt"))
	if err != nil {
		runLog.Close()
		return err
	}
	if verbose {
		t.logger = log.New(io.MultiWriter(os.Stdout, runLog),
			"",
			log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		t.logger = log.New(io.Writer(runLog),
			"",
			log.Ldate|log.Ltime|log.Lshortfile)
	}

	rootSignatureAlgorithm, err := utils.MakeRootCertificate(
		&utils.Config{
			Hostnames: []string{"root.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 25 * time.Hour,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
	)
	if err != nil {
		runLog.Close()
		return err
	}
	t.logger.Printf("Root certificate algorithm: 0x%X\n", rootSignatureAlgorithm)

	intermediateSignatureAlgorithm, err := utils.MakeIntermediateCertificate(
		&utils.Config{
			Hostnames: []string{"example.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 25 * time.Hour,
			ForDC:     true,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
		filepath.Join(testInputsDir, "example.crt"),
		filepath.Join(testInputsDir, "example.key"),
	)
	if err != nil {
		runLog.Close()
		return err
	}
	t.logger.Printf("Intermediate certificate algorithm: 0x%X\n", intermediateSignatureAlgorithm)

	dcValidFor := 24 * time.Hour
	dcAlgorithm, err := utils.MakeDelegatedCredential(
		&utils.Config{
			ValidFor: dcValidFor,
		},
		filepath.Join(testInputsDir, "example.crt"),
		filepath.Join(testInputsDir, "example.key"),
		filepath.Join(testInputsDir, "dc.txt"),
	)
	if err != nil {
		runLog.Close()
		return err
	}
	t.logger.Printf("Delegated credential algorithm: 0x%X\n", dcAlgorithm)
	t.logger.Printf("DC valid for: %v\n", dcValidFor)

	t.logFile = runLog
	return nil
}

func (t *testcaseDC) run(client endpoint, server endpoint) (result resultType, err error) {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	cmd := exec.Command("docker-compose", "up",
		"-V",
		"--no-build",
		"--abort-on-container-exit")

	env := os.Environ()
	env = append(env, fmt.Sprintf("SERVER=%s", server.name))
	env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
	env = append(env, fmt.Sprintf("TESTCASE=%s", t.name))
	// SERVER_SRC and CLIENT_SRC should not be needed, since the images
	// should be built and tagged by this point. They're just set to suppress
	// unset variable warnings by docker-compose.
	env = append(env, "SERVER_SRC=\"\"")
	env = append(env, "CLIENT_SRC=\"\"")
	cmd.Env = env

	var cmdOut bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		result = resultError
		goto runUnsuccessful
	}

	err = waitWithTimeout(cmd, t.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 64") {
			err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
			result = resultUnsupported
			goto runUnsuccessful
		}
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		result = resultFailure
		goto runUnsuccessful
	}

	t.logger.Println("OUT: " + cmdOut.String())
	t.logger.Printf("%s completed without error.\n", fn.Name())
	return resultSuccess, nil

runUnsuccessful:
	t.logger.Println("OUT: " + cmdOut.String())
	t.logger.Println("ERROR: " + fmt.Sprint(err) + ": " + stderr.String())
	return result, err
}

func (t *testcaseDC) verify() (resultType, error) {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	err := pcap.FindTshark()
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultError, err
	}

	pcapPath := filepath.Join(testOutputsDir, "client_node_trace.pcap")
	keylogPath := filepath.Join(testOutputsDir, "client_keylog")
	transcript, err := pcap.Parse(pcapPath, keylogPath)
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultFailure, err
	}

	err = pcap.Validate(transcript, t.name)
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultFailure, err
	}

	t.logger.Printf("%s completed without error.\n", fn.Name())
	return resultSuccess, nil
}

func (t *testcaseDC) teardown(moveOutputs bool) error {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	t.logFile.Close()

	if moveOutputs {
		destDir := filepath.Join("generated", fmt.Sprintf("%s-out", t.name))
		err := os.RemoveAll(destDir)
		if err != nil {
			err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
			t.logger.Println(err)
			return err
		}
		err = os.Rename(testOutputsDir, destDir)
		if err != nil {
			err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
			t.logger.Println(err)
			return err
		}
	}
	return nil
}

type testcaseECHAccept struct {
	name      string
	timeout   time.Duration
	outputDir string
	logger    *log.Logger
	logFile   *os.File
}

func (t *testcaseECHAccept) setup(verbose bool) error {
	err := os.RemoveAll(testInputsDir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(testInputsDir, os.ModePerm)
	if err != nil {
		return err
	}

	err = os.RemoveAll(testOutputsDir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(testOutputsDir, os.ModePerm)
	if err != nil {
		return err
	}
	runLog, err := os.Create(filepath.Join(testOutputsDir, "run-log.txt"))
	if err != nil {
		runLog.Close()
		return err
	}
	if verbose {
		t.logger = log.New(io.MultiWriter(os.Stdout, runLog),
			"",
			log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		t.logger = log.New(io.Writer(runLog),
			"",
			log.Ldate|log.Ltime|log.Lshortfile)
	}

	rootSignatureAlgorithm, err := utils.MakeRootCertificate(
		&utils.Config{
			Hostnames: []string{"root.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 25 * time.Hour,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
	)
	if err != nil {
		runLog.Close()
		return err
	}
	t.logger.Printf("Root certificate algorithm: 0x%X\n", rootSignatureAlgorithm)

	intermediateSignatureAlgorithm, err := utils.MakeIntermediateCertificate(
		&utils.Config{
			Hostnames: []string{"example.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 25 * time.Hour,
			ForDC:     true,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
		filepath.Join(testInputsDir, "example.crt"),
		filepath.Join(testInputsDir, "example.key"),
	)
	if err != nil {
		runLog.Close()
		return err
	}
	t.logger.Printf("example.com intermediate certificate algorithm: 0x%X\n", intermediateSignatureAlgorithm)

	intermediateSignatureAlgorithm, err = utils.MakeIntermediateCertificate(
		&utils.Config{
			Hostnames: []string{"client-facing.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 25 * time.Hour,
			ForDC:     true,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
		filepath.Join(testInputsDir, "client-facing.crt"),
		filepath.Join(testInputsDir, "client-facing.key"),
	)
	if err != nil {
		runLog.Close()
		return err
	}
	t.logger.Printf("client-facing.com intermediate certificate algorithm: 0x%X\n", intermediateSignatureAlgorithm)

	err = utils.MakeECHKey(
		utils.ECHConfigTemplate{
			Id:         123, // This is chosen at random by the client-facing server.
			PublicName: "client-facing.com",
			Version:    utils.ECHVersionDraft13,
			KemId:      uint16(hpke.KEM_X25519_HKDF_SHA256),
			KdfIds: []uint16{
				uint16(hpke.KDF_HKDF_SHA256),
			},
			AeadIds: []uint16{
				uint16(hpke.AEAD_AES128GCM),
			},
			MaximumNameLength: 0,
		},
		filepath.Join(testInputsDir, "ech_configs"),
		filepath.Join(testInputsDir, "ech_key"),
	)
	if err != nil {
		runLog.Close()
		return err
	}

	t.logFile = runLog
	return nil

}

func (t *testcaseECHAccept) run(client endpoint, server endpoint) (result resultType, err error) {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	cmd := exec.Command("docker-compose", "up",
		"-V",
		"--no-build",
		"--abort-on-container-exit")

	env := os.Environ()
	env = append(env, fmt.Sprintf("SERVER=%s", server.name))
	env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
	env = append(env, fmt.Sprintf("TESTCASE=%s", t.name))
	// SERVER_SRC and CLIENT_SRC should not be needed, since the images
	// should be built and tagged by this point. They're just set to suppress
	// unset variable warnings by docker-compose.
	env = append(env, "SERVER_SRC=\"\"")
	env = append(env, "CLIENT_SRC=\"\"")
	cmd.Env = env

	var cmdOut bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		result = resultError
		goto runUnsuccessful
	}

	err = waitWithTimeout(cmd, t.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 64") {
			err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
			result = resultUnsupported
			goto runUnsuccessful
		}
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		result = resultFailure
		goto runUnsuccessful
	}

	t.logger.Println("OUT: " + cmdOut.String())
	t.logger.Printf("%s completed without error.\n", fn.Name())
	return resultSuccess, nil

runUnsuccessful:
	t.logger.Println("OUT: " + cmdOut.String())
	t.logger.Println("ERROR: " + fmt.Sprint(err) + ": " + stderr.String())
	return result, err
}

func (t *testcaseECHAccept) verify() (resultType, error) {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	err := pcap.FindTshark()
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultError, err
	}

	pcapPath := filepath.Join(testOutputsDir, "client_node_trace.pcap")
	keylogPath := filepath.Join(testOutputsDir, "client_keylog")
	transcript, err := pcap.Parse(pcapPath, keylogPath)
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultFailure, err
	}

	err = pcap.Validate(transcript, t.name)
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultFailure, err
	}

	t.logger.Printf("%s completed without error.\n", fn.Name())
	return resultSuccess, nil
}

func (t *testcaseECHAccept) teardown(moveOutputs bool) error {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	t.logFile.Close()

	if moveOutputs {
		destDir := filepath.Join("generated", fmt.Sprintf("%s-out", t.name))
		err := os.RemoveAll(destDir)
		if err != nil {
			err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
			t.logger.Println(err)
			return err
		}
		err = os.Rename(testOutputsDir, destDir)
		if err != nil {
			err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
			t.logger.Println(err)
			return err
		}
	}
	return nil
}

var testcases = map[string]testcase{
	"dc": &testcaseDC{
		name:    "dc",
		timeout: 100 * time.Second},
	"ech-accept": &testcaseECHAccept{
		name:    "ech-accept",
		timeout: 100 * time.Second},
}
