package relay

import cascadia "git.sharegap.net/cascadia/cascadia-go"

const (
	KindRepositoryAnnouncement = 30617
	KindRepositoryState        = 30618
	KindContextVMIntent        = cascadia.CAS_INTENT
	KindCheckRunResult         = 30315
	KindCASAudit               = cascadia.CAS_AUDIT
	KindPatch                  = 1617
	KindPROpen                 = 1618
	KindPRUpdate               = 1619
	KindIssue                  = 1621
	KindStatusOpen             = 1630
	KindStatusApplied          = 1631
	KindStatusClosed           = 1632
	KindStatusDraft            = 1633
	KindNIP22Comment           = 1111
	KindNIP32Label             = 1985
	KindLoomWorkerAd           = cascadia.CAS_WORKER_AD
	KindLoomJobRequest         = 5100
	KindLoomJobResult          = 5101
	KindLoomJobCancel          = 5102
	KindLoomJobStatus          = 30100
	KindHiveWorkflowRun        = 5401
	KindHiveWorkflowResult     = 5402
)
