package bridge

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBridgeSessionManifestsAreOwnerOnlyAndDoNotPersistErrorDetail(t *testing.T) {
	const privateMarker = "private-error-marker.example"
	for _, test := range []struct {
		name  string
		write func(*Session, time.Time, time.Time, error) error
		want  string
	}{
		{
			name: "fast",
			write: func(session *Session, started, stopped time.Time, err error) error {
				return session.writeFastManifest(started, stopped, err)
			},
			want: `"paired_evidence": false`,
		},
		{
			name: "controlled",
			write: func(session *Session, started, stopped time.Time, err error) error {
				return session.writeControlledManifest(started, stopped, ControlledStats{}, err)
			},
			want: `"controlled_options"`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			session := &Session{
				Dir:  directory,
				Host: Adapter{Name: "en11"}, Switch: Adapter{Name: "en12"},
			}
			if err := test.write(
				session, time.Unix(1, 0).UTC(), time.Unix(2, 0).UTC(),
				errors.New("runtime detail "+privateMarker),
			); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "session.json")
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(content)
			if strings.Contains(text, privateMarker) || !strings.Contains(text, sessionErrorMarker(errors.New("failed"))) || !strings.Contains(text, test.want) {
				t.Fatalf("manifest=%s", text)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("manifest mode=%v", info.Mode().Perm())
			}
		})
	}
}
