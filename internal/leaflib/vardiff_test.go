package leaflib

import (
	"math"
	"testing"
	"time"
)

func TestEstimateHashrateHz(t *testing.T) {
	tests := []struct {
		name              string
		hashesAccumulated uint64
		connectedAt       time.Time
		want              float64
		tolerance         float64
	}{
		{
			name:              "zero hashes accumulated returns zero",
			hashesAccumulated: 0,
			connectedAt:       time.Now().Add(-10 * time.Second),
			want:              0,
			tolerance:         0,
		},
		{
			name:              "10000 hashes over 10 seconds is approximately 1000 H/s",
			hashesAccumulated: 10000,
			connectedAt:       time.Now().Add(-10 * time.Second),
			want:              1000.0,
			tolerance:         5,
		},
		{
			name:              "future connectedAt returns zero regardless of hashes",
			hashesAccumulated: 12345,
			connectedAt:       time.Now().Add(1 * time.Hour),
			want:              0,
			tolerance:         0,
		},
		{
			name:              "53 shares at difficulty 10000 over 30 minutes is approximately 294.4 H/s",
			hashesAccumulated: 53 * 10000,
			connectedAt:       time.Now().Add(-30 * time.Minute),
			want:              530000.0 / 1800.0,
			tolerance:         3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EstimateHashrateHz(tt.hashesAccumulated, tt.connectedAt)
			if math.Abs(got-tt.want) > tt.tolerance {
				t.Errorf("EstimateHashrateHz(%d, %v) = %v, want %v (tolerance %v)",
					tt.hashesAccumulated, tt.connectedAt, got, tt.want, tt.tolerance)
			}
		})
	}
}
