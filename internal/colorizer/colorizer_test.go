package colorizer

import (
	"internal/colorizer"
	"testing"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

const (
	fgOrange uint8 = 208
)

func TestGetSeverityColor(t *testing.T) {
	tests := []struct {
		name          string
		severity      interface{}
		expectedColor string
	}{
		{
			name:          "Test severity info",
			severity:      severity.Info,
			expectedColor: aurora.Blue(severity.Info.String()).String(),
		},
		{
			name:          "Test severity low",
			severity:      severity.Low,
			expectedColor: aurora.Green(severity.Low.String()).String(),
		},
		{
			name:          "Test severity medium",
			severity:      severity.Medium,
			expectedColor: aurora.Yellow(severity.Medium.String()).String(),
		},
		{
			name:          "Test severity high",
			severity:      severity.High,
			expectedColor: aurora.Index(fgOrange, severity.High.String()).String(),
		},
		{
			name:          "Test severity critical",
			severity:      severity.Critical,
			expectedColor: aurora.Red(severity.Critical.String()).String(),
		},
		{
			name:          "Test severity unknown",
			severity:      severity.Unknown,
			expectedColor: aurora.White(severity.Unknown.String()).String(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualColor := colorizer.GetSeverityColor(tc.severity)

			if actualColor != tc.expectedColor {
				t.Errorf("GetSeverityColor returned incorrect color.\nExpected: %s\nActual: %s", tc.expectedColor, actualColor)
			}
		})
	}
}
