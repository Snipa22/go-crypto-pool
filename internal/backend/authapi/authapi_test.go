package authapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

const testSecret = "test-secret-key-do-not-use-in-prod"

// fakeRepo is an in-memory Repository test double, keyed by both
// username and id (mirroring db.Repository's dual
// GetUserByUsername/GetUserByID lookups).
type fakeRepo struct {
	byUsername map[string]*User
	byID       map[int64]*User
	nextID     int64

	forcePayoutCalls []forcePayoutCall
	forcePayoutErr   error
}

type forcePayoutCall struct {
	Algo, Network, PaymentAddress string
	PaymentID                     *string
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{byUsername: map[string]*User{}, byID: map[int64]*User{}}
}

func (f *fakeRepo) addUser(u User) *User {
	f.nextID++
	u.ID = f.nextID
	cp := u
	f.byUsername[u.Username] = &cp
	f.byID[cp.ID] = &cp
	return &cp
}

func (f *fakeRepo) GetUserByUsername(_ context.Context, username string) (User, error) {
	u, ok := f.byUsername[username]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return *u, nil
}

func (f *fakeRepo) GetUserByID(_ context.Context, id int64) (User, error) {
	u, ok := f.byID[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return *u, nil
}

func (f *fakeRepo) UpdateUserPassword(_ context.Context, id int64, passHash string) error {
	u, ok := f.byID[id]
	if !ok {
		return ErrUserNotFound
	}
	u.Pass = &passHash
	f.byUsername[u.Username] = u
	return nil
}

func (f *fakeRepo) ToggleUserEnableEmail(_ context.Context, id int64) error {
	u, ok := f.byID[id]
	if !ok {
		return ErrUserNotFound
	}
	u.EnableEmail = !u.EnableEmail
	return nil
}

func (f *fakeRepo) ToggleUserEnableEmailByUsername(_ context.Context, username string) error {
	u, ok := f.byUsername[username]
	if !ok {
		return nil // no-op, mirrors legacy semantics
	}
	u.EnableEmail = !u.EnableEmail
	return nil
}

func (f *fakeRepo) UpdateUserPayoutThreshold(_ context.Context, id int64, threshold int64) error {
	u, ok := f.byID[id]
	if !ok {
		return ErrUserNotFound
	}
	u.PayoutThreshold = threshold
	return nil
}

func (f *fakeRepo) UpsertUserThreshold(_ context.Context, username string, threshold int64) error {
	if u, ok := f.byUsername[username]; ok {
		u.PayoutThreshold = threshold
		return nil
	}
	f.addUser(User{Username: username, Email: "null@null.null", PayoutThreshold: threshold})
	return nil
}

func (f *fakeRepo) SetForcePayout(_ context.Context, algo, network, paymentAddress string, paymentID *string) error {
	if f.forcePayoutErr != nil {
		return f.forcePayoutErr
	}
	f.forcePayoutCalls = append(f.forcePayoutCalls, forcePayoutCall{Algo: algo, Network: network, PaymentAddress: paymentAddress, PaymentID: paymentID})
	return nil
}

func newTestHandler(t *testing.T, repo Repository) *Handler {
	t.Helper()
	h, err := NewHandler(repo, Config{JWTSecret: testSecret, Network: poolpb.Network_NETWORK_TESTNET})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func doReq(t *testing.T, mux *http.ServeMux, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	return rr
}

func TestNewHandler_RequiresJWTSecret(t *testing.T) {
	if _, err := NewHandler(newFakeRepo(), Config{}); err == nil {
		t.Fatal("expected error for empty JWTSecret, got nil")
	}
}

func TestAuthenticate_Success(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	hash := h.hashPassword("hunter2")
	repo.addUser(User{Username: "alice", Pass: &hash, Admin: true})

	mux := h.Mux()
	rr := doReq(t, mux, http.MethodPost, "/authenticate", `{"username":"alice","password":"hunter2"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["success"] != true {
		t.Fatalf("expected success=true, got %+v", resp)
	}
	token, _ := resp["msg"].(string)
	if token == "" {
		t.Fatal("expected a non-empty token in msg")
	}

	claims, err := h.parseToken(token)
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if claims.ID != 1 || !claims.Admin {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestAuthenticate_WrongPassword(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	hash := h.hashPassword("hunter2")
	repo.addUser(User{Username: "alice", Pass: &hash})

	rr := doReq(t, h.Mux(), http.MethodPost, "/authenticate", `{"username":"alice","password":"wrong"}`, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", rr.Code, rr.Body.String())
	}
}

func TestAuthenticate_UnknownUser(t *testing.T) {
	h := newTestHandler(t, newFakeRepo())
	rr := doReq(t, h.Mux(), http.MethodPost, "/authenticate", `{"username":"ghost","password":"x"}`, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAuthenticate_NullPass_DoesNotFallBackToEmail(t *testing.T) {
	// Deliberate deviation from legacy (see package doc comment):
	// a NULL pass must never authenticate, even if the caller
	// supplies the user's own email as the "password".
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "bob", Email: "bob@example.com", Pass: nil})

	rr := doReq(t, h.Mux(), http.MethodPost, "/authenticate", `{"username":"bob","password":"bob@example.com"}`, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (NULL pass must never authenticate)", rr.Code)
	}
}

func TestAuthenticate_MissingFields(t *testing.T) {
	h := newTestHandler(t, newFakeRepo())
	cases := []string{`{"username":"a"}`, `{"password":"b"}`, `not json`}
	for _, body := range cases {
		rr := doReq(t, h.Mux(), http.MethodPost, "/authenticate", body, nil)
		if rr.Code != http.StatusBadRequest && rr.Code != http.StatusUnauthorized {
			t.Errorf("body %q: status = %d, want 400 or 401", body, rr.Code)
		}
	}
}

func TestRequireAuth_NoToken(t *testing.T) {
	h := newTestHandler(t, newFakeRepo())
	rr := doReq(t, h.Mux(), http.MethodGet, "/authed/", "", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["success"] != false || resp["msg"] != "No token provided." {
		t.Fatalf("unexpected body: %+v", resp)
	}
}

func TestRequireAuth_InvalidToken_Returns200WithSuccessFalse(t *testing.T) {
	// Legacy quirk (see package doc comment): an invalid/expired
	// token is a 200 with success=false, NOT a 401/403.
	h := newTestHandler(t, newFakeRepo())
	rr := doReq(t, h.Mux(), http.MethodGet, "/authed/?token=not-a-real-jwt", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["success"] != false || resp["msg"] != "Failed to authenticate token." {
		t.Fatalf("unexpected body: %+v", resp)
	}
}

func TestRequireAuth_ExpiredToken(t *testing.T) {
	h := newTestHandler(t, newFakeRepo())
	c := claims{
		ID: 1, Admin: false,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatalf("signing expired token: %v", err)
	}

	rr := doReq(t, h.Mux(), http.MethodGet, "/authed/?token="+signed, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["success"] != false {
		t.Fatalf("expected success=false for expired token, got %+v", resp)
	}
}

func TestRequireAuth_TokenSources(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "alice", PayoutThreshold: 42})
	token, err := h.signToken(1, false)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}

	mux := h.Mux()

	t.Run("query param", func(t *testing.T) {
		rr := doReq(t, mux, http.MethodGet, "/authed/?token="+token, "", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("header", func(t *testing.T) {
		rr := doReq(t, mux, http.MethodGet, "/authed/", "", map[string]string{"X-Access-Token": token})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("body field, restored for downstream handler", func(t *testing.T) {
		// changePassword's handler must still be able to decode
		// {"password": ...} from the same body requireAuth already
		// consumed to find "token".
		rr := doReq(t, mux, http.MethodPost, "/authed/changePassword", `{"token":"`+token+`","password":"newpass"}`, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})
}

func TestTokenRefresh(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "alice", Admin: true})
	token, _ := h.signToken(1, true)

	rr := doReq(t, h.Mux(), http.MethodGet, "/authed/tokenRefresh?token="+token, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	newToken := resp["msg"]
	if newToken == "" {
		t.Fatal("expected a non-empty refreshed token")
	}
	claims, err := h.parseToken(newToken)
	if err != nil {
		t.Fatalf("parsing refreshed token: %v", err)
	}
	if claims.ID != 1 || !claims.Admin {
		t.Fatalf("refreshed token lost original claims: %+v", claims)
	}
}

func TestAuthedRoot(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "alice", PayoutThreshold: 1000, EnableEmail: true})
	token, _ := h.signToken(1, false)

	rr := doReq(t, h.Mux(), http.MethodGet, "/authed/?token="+token, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Msg authedInfo `json:"msg"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Msg.PayoutThreshold != 1000 || !resp.Msg.EmailEnabled {
		t.Fatalf("unexpected response: %+v", resp.Msg)
	}
}

func TestChangePassword(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "alice"})
	token, _ := h.signToken(1, false)

	rr := doReq(t, h.Mux(), http.MethodPost, "/authed/changePassword?token="+token, `{"password":"newpass"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	u, _ := repo.GetUserByID(context.Background(), 1)
	if u.Pass == nil || *u.Pass != h.hashPassword("newpass") {
		t.Fatalf("password was not updated correctly: %+v", u)
	}
}

func TestChangePassword_EmptyPassword(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "alice"})
	token, _ := h.signToken(1, false)

	rr := doReq(t, h.Mux(), http.MethodPost, "/authed/changePassword?token="+token, `{"password":""}`, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestToggleEmail_Authed(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "alice", EnableEmail: false})
	token, _ := h.signToken(1, false)

	rr := doReq(t, h.Mux(), http.MethodPost, "/authed/toggleEmail?token="+token, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	u, _ := repo.GetUserByID(context.Background(), 1)
	if !u.EnableEmail {
		t.Fatal("expected enable_email to be toggled true")
	}
}

func TestChangePayoutThreshold(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "alice"})
	token, _ := h.signToken(1, false)

	rr := doReq(t, h.Mux(), http.MethodPost, "/authed/changePayoutThreshold?token="+token, `{"threshold":5000}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["msg"] != "Threshold updated, set to: 5000" {
		t.Fatalf("unexpected msg: %q", resp["msg"])
	}
	u, _ := repo.GetUserByID(context.Background(), 1)
	if u.PayoutThreshold != 5000 {
		t.Fatalf("threshold not persisted: %+v", u)
	}
}

func TestForcePayment_DefaultsAlgoAndNetwork(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo) // Config.Network = TESTNET

	rr := doReq(t, h.Mux(), http.MethodPost, "/user/forcePayment", `{"username":"addr1"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if len(repo.forcePayoutCalls) != 1 {
		t.Fatalf("expected 1 SetForcePayout call, got %d", len(repo.forcePayoutCalls))
	}
	call := repo.forcePayoutCalls[0]
	if call.Algo != "RXM" || call.Network != "TESTNET" || call.PaymentAddress != "addr1" || call.PaymentID != nil {
		t.Fatalf("unexpected call: %+v", call)
	}
}

func TestForcePayment_SplitsPaymentID(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)

	rr := doReq(t, h.Mux(), http.MethodPost, "/user/forcePayment", `{"username":"addr1.deadbeef","algo":"RXT","network":"MAINNET"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	call := repo.forcePayoutCalls[0]
	if call.Algo != "RXT" || call.Network != "MAINNET" || call.PaymentAddress != "addr1" || call.PaymentID == nil || *call.PaymentID != "deadbeef" {
		t.Fatalf("unexpected call: %+v", call)
	}
}

func TestForcePayment_NotFound(t *testing.T) {
	repo := newFakeRepo()
	repo.forcePayoutErr = ErrBalanceNotFound
	h := newTestHandler(t, repo)

	rr := doReq(t, h.Mux(), http.MethodPost, "/user/forcePayment", `{"username":"addr1"}`, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["success"] != false {
		t.Fatalf("unexpected body: %+v", resp)
	}
}

func TestForcePayment_MissingUsername(t *testing.T) {
	h := newTestHandler(t, newFakeRepo())
	rr := doReq(t, h.Mux(), http.MethodPost, "/user/forcePayment", `{}`, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestUpdateThreshold_CreatesUserIfMissing(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)

	rr := doReq(t, h.Mux(), http.MethodPost, "/user/updateThreshold", `{"username":"newuser","threshold":123}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	u, err := repo.GetUserByUsername(context.Background(), "newuser")
	if err != nil {
		t.Fatalf("expected user to be created: %v", err)
	}
	if u.PayoutThreshold != 123 || u.Email != "null@null.null" {
		t.Fatalf("unexpected created user: %+v", u)
	}
}

func TestGetUser_Found(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "addr1", PayoutThreshold: 77, EnableEmail: true})

	rr := doReq(t, h.Mux(), http.MethodGet, "/user/addr1", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Msg authedInfo `json:"msg"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Msg.PayoutThreshold != 77 || !resp.Msg.EmailEnabled {
		t.Fatalf("unexpected response: %+v", resp.Msg)
	}
}

func TestGetUser_NotFound_ReturnsZeroDefaults(t *testing.T) {
	h := newTestHandler(t, newFakeRepo())
	rr := doReq(t, h.Mux(), http.MethodGet, "/user/ghost", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (zero defaults, not an error), body = %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Msg authedInfo `json:"msg"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Msg.PayoutThreshold != 0 || resp.Msg.EmailEnabled {
		t.Fatalf("expected zero-value defaults, got %+v", resp.Msg)
	}
}

func TestToggleEmail_Public(t *testing.T) {
	repo := newFakeRepo()
	h := newTestHandler(t, repo)
	repo.addUser(User{Username: "addr1", EnableEmail: false})

	rr := doReq(t, h.Mux(), http.MethodPost, "/user/toggleEmail", `{"address":"addr1"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	u, _ := repo.GetUserByUsername(context.Background(), "addr1")
	if !u.EnableEmail {
		t.Fatal("expected enable_email to be toggled true")
	}
}

func TestToggleEmail_Public_NoOpIfMissing(t *testing.T) {
	h := newTestHandler(t, newFakeRepo())
	rr := doReq(t, h.Mux(), http.MethodPost, "/user/toggleEmail", `{"address":"ghost"}`, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no-op still succeeds), body = %s", rr.Code, rr.Body.String())
	}
}

func TestSplitUsername(t *testing.T) {
	cases := []struct {
		in        string
		addr      string
		paymentID *string
	}{
		{"addr1", "addr1", nil},
	}
	for _, tc := range cases {
		addr, pid := splitUsername(tc.in)
		if addr != tc.addr {
			t.Errorf("splitUsername(%q) address = %q, want %q", tc.in, addr, tc.addr)
		}
		if (pid == nil) != (tc.paymentID == nil) {
			t.Errorf("splitUsername(%q) paymentID nilness mismatch", tc.in)
		}
	}
	addr, pid := splitUsername("addr1.paymentid123")
	if addr != "addr1" || pid == nil || *pid != "paymentid123" {
		t.Fatalf("splitUsername with dot: got %q, %v", addr, pid)
	}
}
