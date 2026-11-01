package protocol

import "fmt"

type Code uint16

const (
	OrderlyClose       Code = 0
	Malformed          Code = 1
	UnsupportedVersion Code = 2
	BadSignature       Code = 3
	Expired            Code = 4
	Replay             Code = 5
	PolicyChanged      Code = 6
	EntryDenied        Code = 7
	StaleCard          Code = 8
	Offline            Code = 9
	Busy               Code = 10
	RateLimited        Code = 11
	StreamClosed       Code = 12
	Timeout            Code = 13
	ClockSkew          Code = 14
	NotFound           Code = 15
	StorageUnavailable Code = 16
)

func (c Code) Error() string { return fmt.Sprintf("protocol error %d", uint16(c)) }

var Kinds = [][2]any{
	{1, "INFO_REQUEST"},
	{2, "INFO"},
	{3, "DIRECTORY_QUERY"},
	{4, "DIRECTORY_PAGE"},
	{5, "REGISTER"},
	{6, "REGISTERED"},
	{7, "CARD"},
	{8, "ACK"},
	{9, "LINK_CHALLENGE"},
	{10, "LINK_AUTH"},
	{11, "LINK_READY"},
	{12, "HEARTBEAT"},
	{13, "ROUTE_OPEN"},
	{14, "ROUTE_OFFER"},
	{15, "ROUTE_READY"},
	{16, "ROUTE_CLOSE"},
	{17, "ERROR"},
	{18, "DRAIN"},
	{19, "GREETING"},
	{20, "CHALLENGE"},
	{21, "PROOF"},
	{22, "SEAT_GRANT"},
	{23, "ENTRY_DENIED"},
	{24, "POLICY_CHANGED"},
	{25, "DOOR_SET"},
	{26, "QUEST_CARD"},
	{27, "QUEST_POST"},
	{28, "QUEST_REMOVE"},
	{29, "QUEST_QUERY"},
	{30, "QUEST_PAGE"},
	{31, "QUEST_ACCEPT"},
	{32, "QUEST_RESULT"},
}

const (
	KindInfoRequest    uint16 = 1
	KindInfo           uint16 = 2
	KindDirectoryQuery uint16 = 3
	KindDirectoryPage  uint16 = 4
	KindRegister       uint16 = 5
	KindRegistered     uint16 = 6
	KindCard           uint16 = 7
	KindAck            uint16 = 8
	KindLinkChallenge  uint16 = 9
	KindLinkAuth       uint16 = 10
	KindLinkReady      uint16 = 11
	KindHeartbeat      uint16 = 12
	KindRouteOpen      uint16 = 13
	KindRouteOffer     uint16 = 14
	KindRouteReady     uint16 = 15
	KindRouteClose     uint16 = 16
	KindError          uint16 = 17
	KindDrain          uint16 = 18
	KindGreeting       uint16 = 19
	KindChallenge      uint16 = 20
	KindProof          uint16 = 21
	KindSeatGrant      uint16 = 22
	KindEntryDenied    uint16 = 23
	KindPolicyChanged  uint16 = 24
	KindDoorSet        uint16 = 25
	KindQuestCard      uint16 = 26
	KindQuestPost      uint16 = 27
	KindQuestRemove    uint16 = 28
	KindQuestQuery     uint16 = 29
	KindQuestPage      uint16 = 30
	KindQuestAccept    uint16 = 31
	KindQuestResult    uint16 = 32
)

var Ops = [][2]any{
	{1, "SIGNED_CONTROL"},
	{2, "PING"},
	{3, "PONG"},
	{4, "SESSION_CLOSE"},
	{5, "HTTP_START"},
	{6, "HTTP_BODY"},
	{7, "HTTP_RESPONSE"},
	{8, "HTTP_RESPONSE_BODY"},
	{9, "WS_OPEN"},
	{10, "WS_READY"},
	{11, "WS_DATA"},
	{12, "STREAM_CLOSE"},
}

const (
	OpSignedControl    uint16 = 1
	OpPing             uint16 = 2
	OpPong             uint16 = 3
	OpSessionClose     uint16 = 4
	OpHttpStart        uint16 = 5
	OpHttpBody         uint16 = 6
	OpHttpResponse     uint16 = 7
	OpHttpResponseBody uint16 = 8
	OpWsOpen           uint16 = 9
	OpWsReady          uint16 = 10
	OpWsData           uint16 = 11
	OpStreamClose      uint16 = 12
)

var Errors = [][2]any{
	{0, "orderly close"},
	{1, "MALFORMED"},
	{2, "UNSUPPORTED_VERSION"},
	{3, "BAD_SIGNATURE"},
	{4, "EXPIRED"},
	{5, "REPLAY"},
	{6, "POLICY_CHANGED"},
	{7, "ENTRY_DENIED"},
	{8, "STALE_CARD"},
	{9, "OFFLINE"},
	{10, "BUSY"},
	{11, "RATE_LIMITED"},
	{12, "STREAM_CLOSED"},
	{13, "TIMEOUT"},
	{14, "CLOCK_SKEW"},
	{15, "NOT_FOUND"},
	{16, "STORAGE_UNAVAILABLE"},
}

func ValidateTable(rows [][2]any, start int) error {
	seen := map[string]bool{}
	for i, r := range rows {
		n, ok := r[0].(int)
		s, yes := r[1].(string)
		if !ok || !yes || n != start+i || s == "" || seen[s] {
			return Malformed
		}
		seen[s] = true
	}
	return nil
}
