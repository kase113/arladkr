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
	// Keep one scheduler slot available for the authenticated transport, MVBA,
	// and timers on a multi-core node. A deployment can override this budget
	// explicitly after profiling its own CPU topology.
	if workers > 1 {
		workers--
	}
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

func cvComponentLoadWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_LOAD_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 8 {
		workers = 8
	}
	if workers > jobs {
		workers = jobs
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func cvRSWorkers(jobs int) int {
	if jobs <= 1 {
		return jobs
	}
	workers := runtime.GOMAXPROCS(0)
	if workers > 1 {
		workers--
	}
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_RS_WORKERS"))); err == nil && configured > 0 {
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

// cvNestedMSMWorkers is used inside work that is already parallelized across
// leaves or lanes. Keeping the inner MSM serial prevents multiplicative
// goroutine fan-out while preserving the exact group equation.
func cvNestedMSMWorkers(points int) int {
	if points <= 0 {
		return 0
	}
	return 1
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
