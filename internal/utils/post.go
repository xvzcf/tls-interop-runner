// SPDX-FileCopyrightText: 2021 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
)

const interopResultsURL = "https://tls-interop.crypto-team.workers.dev"

func copyBearerToken() string {
	var token string
	if token = os.Getenv("BEARER_TOKEN"); len(token) == 0 {
		token = "INVALID"
	}
	return token
}

func ProcessTestDirectory(dir string) error {
	var client string
	var server string
	var testcase string
	testData := make(map[string]string)

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		switch f.Name() {
		case "test.txt":
			data, err := ioutil.ReadFile(path.Join(dir, f.Name()))
			if err != nil {
				return err
			}
			params := strings.Split(string(data), ",")
			client = params[0]
			server = params[1]
			testcase = params[2]
			testData["result"] = params[3]
		case "run-log.txt":
			data, err := ioutil.ReadFile(path.Join(dir, f.Name()))
			if err != nil {
				return err
			}
			testData["run"] = string(data)
		}
	}

	if len(client) == 0 || len(server) == 0 || len(testcase) == 0 {
		return nil
	}

	encodedData, err := json.Marshal(testData)
	if err != nil {
		return err
	}

	url := interopResultsURL + "/upload-results?" + fmt.Sprintf("client=%s&server=%s&testcase=%s", client, server, testcase)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(encodedData))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Upload-Bearer-Token", copyBearerToken())

	httpClient := &http.Client{}
	response, err := httpClient.Do(request)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Request failed with status code %d", response.StatusCode)
	}

	return nil
}

func ProcessTestResults(root string) error {
	files, err := ioutil.ReadDir(root)
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.IsDir() && strings.HasSuffix(f.Name(), "-out") {
			err := ProcessTestDirectory(path.Join(root, f.Name()))
			if err != nil {
				return err
			}
		}
	}
	return nil
}
