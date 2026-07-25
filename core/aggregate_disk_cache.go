package core

import (
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func aggregateCacheDir(cfg Config) string {
	if cfg.runtime == nil || cfg.ArtifactCacheDir == "" {
		return ""
	}
	return filepath.Join(
		cfg.ArtifactCacheDir,
		safeCacheComponent(cfg.SID),
		fmt.Sprintf("epoch-%d-n-%d-f-%d-provider-%s", cfg.Epoch, len(cfg.runtime.oldOrder), cfg.F, safeCacheComponent(cfg.APVSSProvider)),
		"aggregates",
	)
}

func aggregateCachePath(cfg Config, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(aggregateCacheDir(cfg), fmt.Sprintf("%x.gob", sum[:]))
}

func readAggregateCache(path string) (*APVSSAggregate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var agg APVSSAggregate
	if err := gob.NewDecoder(f).Decode(&agg); err != nil {
		return nil, err
	}
	return cloneAPVSSAggregate(&agg), nil
}

func writeAggregateCache(path string, agg *APVSSAggregate) error {
	if agg == nil {
		return fmt.Errorf("nil aggregate")
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	encErr := gob.NewEncoder(f).Encode(agg)
	closeErr := f.Close()
	if encErr != nil {
		_ = os.Remove(tmp)
		return encErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, path)
}

func buildOrLoadTrustedAggregateCache(
	cfg Config,
	key string,
	build func() (*APVSSAggregate, error),
) (*APVSSAggregate, error) {
	dir := aggregateCacheDir(cfg)
	if dir == "" {
		return build()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := aggregateCachePath(cfg, key)
	if agg, err := readAggregateCache(path); err == nil {
		return agg, nil
	}

	lockPath := path + ".lock"
	lockFile, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if lockErr == nil {
		_, _ = fmt.Fprintf(lockFile, "pid=%d time=%d\n", os.Getpid(), time.Now().Unix())
		_ = lockFile.Close()
		defer os.Remove(lockPath)
		agg, err := build()
		if err != nil {
			return nil, err
		}
		if err := writeAggregateCache(path, agg); err != nil {
			return nil, err
		}
		return cloneAPVSSAggregate(agg), nil
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if agg, err := readAggregateCache(path); err == nil {
			return agg, nil
		}
		if st, err := os.Stat(lockPath); err == nil && time.Since(st.ModTime()) > 2*time.Minute {
			_ = os.Remove(lockPath)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return build()
}
