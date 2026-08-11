package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"rladkr_go/core"
)

func main() {
	var (
		sid             = flag.String("sid", "cv-v2-reference", "experiment session identifier")
		epoch           = flag.Int("epoch", 1, "experiment epoch")
		oldNodes        = flag.Int("old-n", 7, "old committee size")
		oldFaults       = flag.Int("old-f", 2, "old committee fault bound")
		newNodes        = flag.Int("new-n", 4, "new committee size")
		newFaults       = flag.Int("new-f", 1, "new committee fault bound")
		proposerSample  = flag.Int("proposer-sample", 3, "eligibility proposer sample size")
		validatorSample = flag.Int("validator-sample", 3, "eligibility validator sample size")
		runs            = flag.Int("runs", 1, "number of independent reference epochs")
	)
	flag.Parse()
	if *runs <= 0 || *oldNodes <= 0 || *newNodes <= 0 {
		fmt.Fprintln(os.Stderr, "runs and committee sizes must be positive")
		os.Exit(2)
	}
	oldRoster := make([]int, *oldNodes)
	newRoster := make([]int, *newNodes)
	for i := range oldRoster {
		oldRoster[i] = i
	}
	for i := range newRoster {
		newRoster[i] = *oldNodes + i
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	for run := 0; run < *runs; run++ {
		scratch, err := os.MkdirTemp("", "arladkr-cvv2ref-")
		if err != nil {
			fmt.Fprintf(os.Stderr, "CV_V2_REFERENCE_ERROR run=%d err=%v\n", run+1, err)
			os.Exit(1)
		}
		cfg := core.Config{
			SID: fmt.Sprintf("%s-run-%d", *sid, run+1), Epoch: *epoch,
			OldCommittee: oldRoster, NewCommittee: newRoster,
			OldFaults: *oldFaults, NewFaults: *newFaults,
			CVProposerSampleSize: *proposerSample, CVValidatorSampleSize: *validatorSample,
		}
		result, runErr := core.RunCVV2ReferenceExperiment(cfg, scratch)
		removeErr := os.RemoveAll(scratch)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "CV_V2_REFERENCE_ERROR run=%d err=%v\n", run+1, runErr)
			os.Exit(1)
		}
		if removeErr != nil {
			fmt.Fprintf(os.Stderr, "CV_V2_REFERENCE_ERROR run=%d cleanup=%v\n", run+1, removeErr)
			os.Exit(1)
		}
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "CV_V2_REFERENCE_ERROR run=%d encode=%v\n", run+1, err)
			os.Exit(1)
		}
	}
}
