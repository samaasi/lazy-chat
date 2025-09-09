package ui

import (
	"fmt"
	"strings"
	"time"
)

// ProgressBar represents a console progress bar
type ProgressBar struct {
	title       string
	total       int64
	current     int64
	width       int
	startTime   time.Time
	lastUpdate  time.Time
	updateRate  time.Duration
	completed   bool
}

// NewProgressBar creates a new progress bar
func NewProgressBar(title string, total int64) *ProgressBar {
	return &ProgressBar{
		title:      title,
		total:      total,
		width:      50,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
		updateRate: 100 * time.Millisecond, // Update every 100ms
	}
}

// Update updates the progress bar with new progress
func (pb *ProgressBar) Update(current int64) {
	pb.current = current
	now := time.Now()
	
	// Only update display if enough time has passed or if completed
	if now.Sub(pb.lastUpdate) >= pb.updateRate || current >= pb.total {
		pb.display()
		pb.lastUpdate = now
	}
	
	if current >= pb.total {
		pb.completed = true
	}
}

// Finish marks the progress bar as completed
func (pb *ProgressBar) Finish() {
	pb.current = pb.total
	pb.completed = true
	pb.display()
	fmt.Println() // Add a newline after completion
}

// display renders the progress bar to the console
func (pb *ProgressBar) display() {
	percentage := float64(pb.current) / float64(pb.total) * 100
	if percentage > 100 {
		percentage = 100
	}
	
	// Calculate filled width
	filledWidth := int(float64(pb.width) * percentage / 100)
	
	// Create progress bar string
	bar := "["
	bar += strings.Repeat("=", filledWidth)
	if filledWidth < pb.width {
		bar += ">"
		bar += strings.Repeat(" ", pb.width-filledWidth-1)
	}
	bar += "]"
	
	// Calculate transfer rate and ETA
	elapsed := time.Since(pb.startTime)
	var rate float64
	var eta string
	
	if elapsed.Seconds() > 0 {
		rate = float64(pb.current) / elapsed.Seconds()
		if rate > 0 && pb.current < pb.total {
			remaining := float64(pb.total-pb.current) / rate
			eta = formatDuration(time.Duration(remaining) * time.Second)
		} else {
			eta = "--:--"
		}
	} else {
		eta = "--:--"
	}
	
	// Format the complete progress line
	progressLine := fmt.Sprintf("\r%s %s %.1f%% (%s/%s) %s/s ETA: %s",
		pb.title,
		bar,
		percentage,
		formatBytes(pb.current),
		formatBytes(pb.total),
		formatBytes(int64(rate)),
		eta,
	)
	
	fmt.Print(progressLine)
}

// formatBytes formats bytes into human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatDuration formats duration into human readable format
func formatDuration(d time.Duration) string {
	totalSeconds := int(d.Seconds())
	hours := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	
	if hours > 0 {
		return fmt.Sprintf("%d:%02d:%02d", hours, minutes, seconds)
	}
	return fmt.Sprintf("%d:%02d", minutes, seconds)
}

// MultiProgressManager manages multiple progress bars
type MultiProgressManager struct {
	bars map[string]*ProgressBar
}

// NewMultiProgressManager creates a new multi-progress manager
func NewMultiProgressManager() *MultiProgressManager {
	return &MultiProgressManager{
		bars: make(map[string]*ProgressBar),
	}
}

// AddProgress adds a new progress bar
func (mpm *MultiProgressManager) AddProgress(id, title string, total int64) {
	mpm.bars[id] = NewProgressBar(title, total)
}

// UpdateProgress updates a specific progress bar
func (mpm *MultiProgressManager) UpdateProgress(id string, current int64) {
	if bar, exists := mpm.bars[id]; exists {
		bar.Update(current)
	}
}

// FinishProgress marks a progress bar as completed
func (mpm *MultiProgressManager) FinishProgress(id string) {
	if bar, exists := mpm.bars[id]; exists {
		bar.Finish()
		delete(mpm.bars, id)
	}
}

// RemoveProgress removes a progress bar
func (mpm *MultiProgressManager) RemoveProgress(id string) {
	delete(mpm.bars, id)
}