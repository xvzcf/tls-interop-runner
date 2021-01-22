package main

func isTranscriptValid(transcript Transcript, testCase string) bool {
	switch testCase {
	case "dc":
		if transcript.clientHello.version != 0x0303 {
			return false
		}
		if !transcript.clientHello.supportsDC {
			return false
		}
		if transcript.clientHello.serverName != "example.com" {
			return false
		}
		for _, v := range transcript.clientHello.supportedVersions {
			if v == 0x0304 {
				return true
			}
		}
	}
	return false
}
