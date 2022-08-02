// SPDX-FileCopyrightText: 2022 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type result struct {
	Abbr   string `json:"abbr"`
	Name   string `json:"name"`
	Result string `json:"result"`
}

type testInfo struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type resultsSummary struct {
	Servers []string            `json:"servers"`
	Clients []string            `json:"clients"`
	Results [][]result          `json:"results"`
	Tests   map[string]testInfo `json:"tests"`
	URLS    map[string]string   `json:"urls"`
}

func processTestResults(resultsDir string) error {
	if _, err := os.Stat(resultsDir); err != nil {
		return err
	}

	var summary resultsSummary
	summary.Servers = getServers()
	summary.Clients = getClients()
	testcaseNames := getTestcaseNamesSorted()
	summary.Results = make([][]result, len(summary.Clients)*len(summary.Servers))

	l := 0
	for i := range summary.Clients {
		for j := range summary.Servers {
			summaryFilePath := filepath.Join(resultsDir, fmt.Sprintf("summary_%s_%s.txt", summary.Clients[i], summary.Servers[j]))
			summaryFile, err := os.Open(summaryFilePath)
			if err != nil {
				for k := range testcaseNames {
					testMetadata := testcases[testcaseNames[k]].getMetadata()
					summary.Results[l] = append(summary.Results[l], result{
						Abbr:   testMetadata.abbrev,
						Name:   testMetadata.name,
						Result: resultSkipped.String(),
					})
				}
			} else {
				defer summaryFile.Close()
				fscanner := bufio.NewScanner(summaryFile)
				for fscanner.Scan() {
					testInfoSeparated := strings.Split(fscanner.Text(), ",")
					testMetadata := testcases[testInfoSeparated[2]].getMetadata()
					summary.Results[l] = append(summary.Results[l], result{
						Abbr:   testMetadata.abbrev,
						Name:   testMetadata.name,
						Result: strings.TrimSuffix(testInfoSeparated[3], "\n"),
					})
				}
			}
			l++
		}
	}

	summary.Tests = make(map[string]testInfo)
	for _, t := range testcases {
		testMetadata := t.getMetadata()
		summary.Tests[testMetadata.abbrev] = testInfo{Name: testMetadata.name, Desc: testMetadata.desc}
	}

	summary.URLS = make(map[string]string)
	for _, e := range endpoints {
		summary.URLS[e.name] = e.url
	}

	summaryJson, _ := json.MarshalIndent(summary, "", "    ")
	err := ioutil.WriteFile(filepath.Join(resultsDir, "summary.json"), summaryJson, 0644)
	if err != nil {
		return err
	}
	return nil
}
