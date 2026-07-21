package relay

import cascadia "git.sharegap.net/cascadia/cascadia-go"

const (
	KindRepositoryAnnouncement = 30617
	KindRepositoryState        = 30618
	KindContextVMIntent        = cascadia.CAS_INTENT
	KindPatch                  = 1617
	KindPROpen                 = 1618
	KindPRUpdate               = 1619
	KindIssue                  = 1621
	KindStatusOpen             = 1630
	KindStatusApplied          = 1631
	KindStatusClosed           = 1632
	KindStatusDraft            = 1633
	KindNIP32Label             = 1985
)
