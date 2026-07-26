package core

import "testing"

func TestCVCryptoWorkerBudget(t *testing.T) {
	t.Setenv("RLADKR_CRYPTO_WORKERS", "3")
	if got := cvCryptoWorkers(10); got != 3 {
		t.Fatalf("configured crypto workers=%d, want 3", got)
	}
	if got := cvCryptoWorkers(2); got != 2 {
		t.Fatalf("job-limited crypto workers=%d, want 2", got)
	}
	t.Setenv("RLADKR_CRYPTO_WORKERS", "99")
	if got := cvCryptoWorkers(10); got != 4 {
		t.Fatalf("capped crypto workers=%d, want 4", got)
	}
	if got := cvNestedMSMWorkers(64); got != 1 {
		t.Fatalf("nested MSM workers=%d, want 1", got)
	}
	t.Setenv("RLADKR_COMPONENT_LOAD_WORKERS", "5")
	if got := cvComponentLoadWorkers(10); got != 5 {
		t.Fatalf("configured component load workers=%d, want 5", got)
	}
	t.Setenv("RLADKR_RS_WORKERS", "2")
	if got := cvRSWorkers(10); got != 2 {
		t.Fatalf("configured RS workers=%d, want 2", got)
	}
}
