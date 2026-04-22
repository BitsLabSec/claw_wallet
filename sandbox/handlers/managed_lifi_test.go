package handlers

import (
	"testing"
	"time"
)

func TestScheduleLifiTaskCleanupDeletesTask(t *testing.T) {
	oldRetention := lifiTaskRetention
	defer func() {
		lifiTaskRetention = oldRetention
	}()

	uid := "cleanup-test"
	lifiTaskStatusMap.Store(uid, &LifiStatusResponse{Status: "FAILED"})
	defer lifiTaskStatusMap.Delete(uid)

	lifiTaskRetention = 10 * time.Millisecond
	scheduleLifiTaskCleanup(uid)

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := lifiTaskStatusMap.Load(uid); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("expected LI.FI task cleanup to delete task status")
}

func TestExecuteManagedLifiQuoteRejectsBitcoin(t *testing.T) {
	_, err := executeManagedLifiQuote(&LifiBridgeRequest{
		FromChainID: "20000000000001",
		ToChainID:   "1",
		FromAddress: "btc-source",
		ToAddress:   "evm-destination",
	})
	if err == nil {
		t.Fatal("expected bitcoin LI.FI quote to be rejected")
	}
	if err.Error() != "bitcoin is not supported for LI.FI bridge yet" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStoreLifiTaskStatusUpdatesMap(t *testing.T) {
	uid := "status-test"
	defer lifiTaskStatusMap.Delete(uid)

	storeLifiTaskStatus(uid, &LifiStatusResponse{Status: "FAILED", Message: "panic: boom"})

	val, ok := lifiTaskStatusMap.Load(uid)
	if !ok {
		t.Fatal("expected LI.FI task status to be stored")
	}
	status, _ := val.(*LifiStatusResponse)
	if status == nil || status.Status != "FAILED" || status.Message != "panic: boom" {
		t.Fatalf("unexpected stored status: %+v", status)
	}
}
