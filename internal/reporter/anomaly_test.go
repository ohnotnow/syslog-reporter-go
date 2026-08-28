package reporter

// Port of tests/test_anomaly_agent.py from the Python original.

import (
	"math"
	"strings"
	"testing"
)

func TestParseLineStandardLine(t *testing.T) {
	rec := ParseLine("Nov  8 00:10:04 james puppet-agent[1545710]: Requesting catalog")
	if rec == nil {
		t.Fatal("expected a parse")
	}
	if rec.Host != "james" || rec.Program != "puppet-agent" || rec.Window != "00:10" {
		t.Errorf("got %+v", rec)
	}
	if !strings.HasSuffix(rec.Raw, "Requesting catalog") {
		t.Errorf("raw = %q", rec.Raw)
	}
}

func TestParseLineStripsPathAndPid(t *testing.T) {
	rec := ParseLine("Nov  8 09:14:01 box /usr/libexec/gdm-x-session[20413]: hi")
	if rec == nil || rec.Program != "/usr/libexec/gdm-x-session" {
		t.Errorf("got %+v", rec)
	}
}

func TestParseLineProgramWithoutPid(t *testing.T) {
	rec := ParseLine("Nov  8 00:00:00 hastings kernel: [123] segfault")
	if rec == nil || rec.Program != "kernel" {
		t.Errorf("got %+v", rec)
	}
}

func TestParseLineWindowBucketing(t *testing.T) {
	if w := ParseLine("Nov  8 11:37:00 h prog: x").Window; w != "11:30" {
		t.Errorf("window = %q, want 11:30", w)
	}
	if w := ParseLine("Nov  8 11:00:00 h prog: x").Window; w != "11:00" {
		t.Errorf("window = %q, want 11:00", w)
	}
}

func TestParseLineRejectsMalformed(t *testing.T) {
	if ParseLine("too short") != nil {
		t.Error("expected nil for short line")
	}
	if ParseLine("") != nil {
		t.Error("expected nil for empty line")
	}
}

func TestRobustZFlagsOutlier(t *testing.T) {
	pop := []float64{10, 11, 9, 10, 12, 500}
	if z := RobustZ(500, pop); z <= 10 {
		t.Errorf("robust z for outlier = %v, want > 10", z)
	}
	if z := math.Abs(RobustZ(10, pop)); z >= 1 {
		t.Errorf("robust z for normal value = %v, want < 1", z)
	}
}

func TestRobustZIdenticalPopulationIsZero(t *testing.T) {
	if z := RobustZ(5, []float64{5, 5, 5, 5}); z != 0.0 {
		t.Errorf("got %v, want 0", z)
	}
}

func TestRobustZMadZeroFallbackStillRanks(t *testing.T) {
	// MAD is 0 (median deviation 0) but one value spikes: must rank
	// positive, not divide by zero.
	if z := RobustZ(50, []float64{1, 1, 1, 1, 50}); z <= 0 {
		t.Errorf("got %v, want > 0", z)
	}
}

func progs(names ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

func TestGuessOSFamilyRhelSignals(t *testing.T) {
	if f := GuessOSFamily(progs("setroubleshoot", "kernel")); f != "RHEL-family" {
		t.Errorf("got %q", f)
	}
	if f := GuessOSFamily(progs("dnf", "sshd")); f != "RHEL-family" {
		t.Errorf("got %q", f)
	}
}

func TestGuessOSFamilyDebianSignals(t *testing.T) {
	if f := GuessOSFamily(progs("snapd-desktop-i", "kernel")); f != "Debian-family" {
		t.Errorf("got %q", f)
	}
	if f := GuessOSFamily(progs("apt-daily", "dpkg")); f != "Debian-family" {
		t.Errorf("got %q", f)
	}
}

func TestGuessOSFamilyUnknownWhenNoSignal(t *testing.T) {
	if f := GuessOSFamily(progs("sshd", "kernel", "cron")); f != "unknown" {
		t.Errorf("got %q", f)
	}
}

func TestGuessOSFamilyUnknownWhenAmbiguous(t *testing.T) {
	// both families present: don't guess
	if f := GuessOSFamily(progs("setroubleshoot", "apt")); f != "unknown" {
		t.Errorf("got %q", f)
	}
}

func TestPeerDetectorFlagsNoisyHost(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ { // 5 quiet peers, 20 events each
		line := "Nov  8 00:0" + string(rune('0'+i)) + ":00 quiet" + string(rune('0'+i)) + " sshd[1]: ok\n"
		for j := 0; j < 20; j++ {
			lines = append(lines, line)
		}
	}
	for j := 0; j < 2000; j++ { // the offender
		lines = append(lines, "Nov  8 00:00:00 loud sshd[1]: flood\n")
	}

	d := NewPeerDetector(lines)
	d.MinHosts, d.MinCount = 5, 50
	anomalies := d.Run()

	if len(anomalies) == 0 {
		t.Fatal("expected at least one anomaly")
	}
	top := anomalies[0].(*PeerAnomaly)
	if top.Host() != "loud" || top.Program() != "sshd" || top.Count != 2000 {
		t.Errorf("top = %+v", top)
	}
	if !strings.Contains(top.ExampleLine(), "flood") {
		t.Errorf("example = %q", top.ExampleLine())
	}
}

func TestPeerDetectorIgnoresProgramsBelowMinHosts(t *testing.T) {
	// 'niche' appears on only 2 hosts: never peer-compared, however lopsided.
	var lines []string
	for j := 0; j < 1000; j++ {
		lines = append(lines, "Nov  8 00:00:00 a niche[1]: x\n")
	}
	for j := 0; j < 5; j++ {
		lines = append(lines, "Nov  8 00:00:00 b niche[1]: x\n")
	}

	d := NewPeerDetector(lines)
	d.MinHosts, d.MinCount = 5, 50
	for _, a := range d.Run() {
		if a.Program() == "niche" {
			t.Errorf("niche should never be flagged, got %+v", a)
		}
	}
}

func peerFixture(host, program string, score float64) *PeerAnomaly {
	return &PeerAnomaly{host: host, program: program, Count: int(score * 100),
		FleetMedian: 10, score: score, exampleLine: "x"}
}

func baselineFixture(host, program string, score float64) *BaselineAnomaly {
	return &BaselineAnomaly{host: host, program: program, Count: 0,
		BaselineMedian: 500, score: score, Direction: "silent", DaysSeen: 10}
}

func TestCombineDedupesSameHostProgramKeepingStrongest(t *testing.T) {
	peer := peerFixture("boxA", "sshd", 5.0)
	// same series, stronger (negative) signal from the baseline detector
	baseline := baselineFixture("boxA", "sshd", -8.0)
	combined := CombineAnomalies([]Anomaly{peer}, []Anomaly{baseline})
	if len(combined) != 1 {
		t.Fatalf("got %d anomalies, want 1", len(combined))
	}
	if combined[0].Kind() != "baseline" { // |-8| beats |5|
		t.Errorf("kind = %q, want baseline", combined[0].Kind())
	}
}

func TestCombineRanksUnionByAbsoluteScore(t *testing.T) {
	combined := CombineAnomalies(
		[]Anomaly{peerFixture("a", "p", 4.0), peerFixture("b", "q", 9.0)},
		[]Anomaly{baselineFixture("c", "r", -6.0)},
	)
	var got []PairKey
	for _, a := range combined {
		got = append(got, PairKey{a.Host(), a.Program()})
	}
	want := []PairKey{{"b", "q"}, {"c", "r"}, {"a", "p"}}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestCombineEmptyInEmptyOut(t *testing.T) {
	if got := CombineAnomalies(nil, nil, nil); len(got) != 0 {
		t.Errorf("got %#v, want empty", got)
	}
}
