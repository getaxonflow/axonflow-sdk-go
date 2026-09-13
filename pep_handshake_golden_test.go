package axonflow

// These vectors were produced by the platform's reference encoder
// (platform/decision/contract at 857455033) and accepted by its decoder. They
// are extracted verbatim from axonflow-sdk-python's tests/test_pep_handshake.py
// at ef8fd006d, so every SDK pins the same bytes. Capabilities are listed in
// the order GIVEN; for "unsorted" that is not the canonical order.
var goldenPEPHandshakes = []struct {
	name, pepID, audience string
	capabilities          []PEPCapability
	header                string
}{
	{"empty", "sdk-python", "https://pep.example.test", []PEPCapability{}, "eyJwcm9maWxlX3ZlcnNpb24iOjEsInBlcF9pZCI6InNkay1weXRob24iLCJhdWRpZW5jZSI6Imh0dHBzOi8vcGVwLmV4YW1wbGUudGVzdCIsImNhcGFiaWxpdGllcyI6W119"},
	{"unsorted", "gateway.request-1", "urn:example:aud", []PEPCapability{{"field_redact", 2}, {"approval_challenge", 1}, {"field_redact", 1}, {"notification", 3}}, "eyJwcm9maWxlX3ZlcnNpb24iOjEsInBlcF9pZCI6ImdhdGV3YXkucmVxdWVzdC0xIiwiYXVkaWVuY2UiOiJ1cm46ZXhhbXBsZTphdWQiLCJjYXBhYmlsaXRpZXMiOlt7InR5cGUiOiJhcHByb3ZhbF9jaGFsbGVuZ2UiLCJ2ZXJzaW9uIjoxfSx7InR5cGUiOiJmaWVsZF9yZWRhY3QiLCJ2ZXJzaW9uIjoxfSx7InR5cGUiOiJmaWVsZF9yZWRhY3QiLCJ2ZXJzaW9uIjoyfSx7InR5cGUiOiJub3RpZmljYXRpb24iLCJ2ZXJzaW9uIjozfV19"},
	{"minimal", "a", "A", []PEPCapability{{"step_up_authentication", 1}}, "eyJwcm9maWxlX3ZlcnNpb24iOjEsInBlcF9pZCI6ImEiLCJhdWRpZW5jZSI6IkEiLCJjYXBhYmlsaXRpZXMiOlt7InR5cGUiOiJzdGVwX3VwX2F1dGhlbnRpY2F0aW9uIiwidmVyc2lvbiI6MX1dfQ"},
}

// The 64-capability vector, pinned by length and digest: every declared type in
// canonical order at version 1, then 2, and so on, stopping at the count cap.
const (
	sixtyFourPEPHandshakeLen    = 3364
	sixtyFourPEPHandshakeSHA256 = "cdb2b368348bceaed99ca92647afeecd70981604157b60ad66067953a371edbf"
)
