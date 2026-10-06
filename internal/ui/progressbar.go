package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Display is where progress bars are drawn; *Console satisfies it.
type Display interface {
	Status(line string)
	EndStatus()
}

const (
	barWidth       = 30
	redrawInterval = 200 * time.Millisecond
)

// ProgressBar represents a console progress bar. It is safe for concurrent use.
type ProgressBar struct {
	mu         sync.Mutex
	title      string
	total      int64
	current    int64
	startTime  time.Time
	lastDraw   time.Time
	display    Display
	completed  bool
	now        func() time.Time
	drawnOnce  bool
	showOnDone bool
}

// NewProgressBar creates a progress bar drawn on display.
func NewProgressBar(display Display, title string, total int64) *ProgressBar {
	return &ProgressBar{title: title, total: total, display: display, now: time.Now, startTime: time.Now()}
}

// Update sets the current progress and redraws if enough time has passed.
func (pb *ProgressBar) Update(current int64) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.completed {
		return
	}
	pb.current = current
	now := pb.now()
	if now.Sub(pb.lastDraw) >= redrawInterval {
		pb.draw(now)
	}
}

// Finish marks the progress bar as completed and ends its line.
func (pb *ProgressBar) Finish() {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.completed {
		return
	}
	pb.completed = true
	pb.current = pb.total
	pb.draw(pb.now())
	pb.display.EndStatus()
}

// Abort stops the bar without claiming success.
func (pb *ProgressBar) Abort() {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.completed {
		return
	}
	pb.completed = true
	if pb.drawnOnce {
		pb.display.EndStatus()
	}
}

func (pb *ProgressBar) draw(now time.Time) {
	pb.lastDraw = now
	pb.drawnOnce = true
	pb.display.Status(pb.render(now))
}

// render builds the progress line. The caller holds pb.mu.
func (pb *ProgressBar) render(now time.Time) string {
	fraction := 1.0
	if pb.total > 0 {
		fraction = float64(pb.current) / float64(pb.total)
	}
	fraction = max(0, min(1, fraction))

	filled := int(fraction * barWidth)
	bar := strings.Repeat("=", filled)
	if filled < barWidth {
		bar += ">" + strings.Repeat(" ", barWidth-filled-1)
	}

	elapsed := now.Sub(pb.startTime).Seconds()
	var rate float64
	if elapsed > 0 {
		rate = float64(pb.current) / elapsed
	}
	eta := "--:--"
	if rate > 0 && pb.current < pb.total {
		eta = formatDuration(time.Duration(float64(pb.total-pb.current)/rate) * time.Second)
	}

	return fmt.Sprintf("%s [%s] %5.1f%% %s/%s %s/s ETA %s",
		pb.title, bar, fraction*100, formatBytes(pb.current), formatBytes(pb.total), formatBytes(int64(rate)), eta)
}

// FormatBytes formats a byte count in binary units.
func FormatBytes(n int64) string { return formatBytes(n) }

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	total := int(d.Seconds())
	h, m, s := total/3600, total%3600/60, total%60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

// MultiProgressManager manages several progress bars by ID. Safe for
// concurrent use.
type MultiProgressManager struct {
	mu      sync.Mutex
	display Display
	bars    map[string]*ProgressBar
}

// NewMultiProgressManager creates a manager that draws on display.
func NewMultiProgressManager(display Display) *MultiProgressManager {
	return &MultiProgressManager{display: display, bars: make(map[string]*ProgressBar)}
}

// AddProgress adds a new progress bar
func (m *MultiProgressManager) AddProgress(id, title string, total int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bars[id] = NewProgressBar(m.display, title, total)
}

func (m *MultiProgressManager) get(id string) *ProgressBar {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bars[id]
}

// UpdateProgress updates a specific progress bar
func (m *MultiProgressManager) UpdateProgress(id string, current int64) {
	if bar := m.get(id); bar != nil {
		bar.Update(current)
	}
}

// FinishProgress completes a bar and forgets it.
func (m *MultiProgressManager) FinishProgress(id string) {
	m.mu.Lock()
	bar := m.bars[id]
	delete(m.bars, id)
	m.mu.Unlock()
	if bar != nil {
		bar.Finish()
	}
}

// RemoveProgress forgets a bar without completing it.
func (m *MultiProgressManager) RemoveProgress(id string) {
	m.mu.Lock()
	bar := m.bars[id]
	delete(m.bars, id)
	m.mu.Unlock()
	if bar != nil {
		bar.Abort()
	}
}
