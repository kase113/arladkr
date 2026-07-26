package core

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

func cvCryptoWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_CRYPTO_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 4 {
		workers = 4
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// cvRunParallelChecks preserves deterministic error selection while bounding
// the number of concurrent cryptographic jobs per process.
func cvRunParallelChecks(jobs int, check func(int) error) error {
	if jobs <= 0 {
		return nil
	}
	workers := cvCryptoWorkers(jobs)
	if workers == 1 {
		for index := 0; index < jobs; index++ {
			if err := check(index); err != nil {
				return err
			}
		}
		return nil
	}
	errs := make([]error, jobs)
	indices := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range indices {
				errs[index] = check(index)
			}
		}()
	}
	for index := 0; index < jobs; index++ {
		indices <- index
	}
	close(indices)
	group.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
