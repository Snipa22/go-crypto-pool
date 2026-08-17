// Package api implements the backend's HTTP + Protobuf share-ingestion
// endpoints. The backend is a trust boundary, not a validator: it accepts
// leaf-validated shares and does not perform hashing/PoW verification
// itself. This is a scaffold-stage stub — no real handlers yet.
package api

// Handler is a placeholder for the eventual share-ingestion HTTP handler
// set. Real request/response types and Protobuf wiring are not yet
// implemented.
type Handler struct{}

// NewHandler constructs a stub Handler.
func NewHandler() *Handler {
	return &Handler{}
}
