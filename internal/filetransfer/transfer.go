package filetransfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/samaasi/lazy-chat/internal/errors"
	"github.com/samaasi/lazy-chat/internal/interfaces"
	"github.com/samaasi/lazy-chat/internal/ui"
)

// FileTransferMessage represents a file transfer message
type FileTransferMessage struct {
	Type       string `json:"type"`        // "start", "chunk", "complete", "error"
	TransferID string `json:"transfer_id"` // Unique transfer identifier
	FileName   string `json:"file_name"`   // Original file name
	FileSize   int64  `json:"file_size"`   // Total file size in bytes
	ChunkIndex int    `json:"chunk_index"` // Current chunk index
	Data       []byte `json:"data"`        // Chunk data
	Checksum   string `json:"checksum"`    // SHA256 hash
}

// TransferState tracks the state of an ongoing transfer
type TransferState struct {
	TransferID       string
	FileName         string
	FileSize         int64
	BytesTransferred int64
	Status           string // "pending", "active", "completed", "failed"
	PeerID           string
	StartedAt        time.Time
	CompletedAt      time.Time
	ReceivedChunks   map[int][]byte
	TotalChunks      int
	FileHash         string
}

// TransferManager manages file transfers
type TransferManager struct {
	mu              sync.RWMutex
	activeTransfers map[string]*TransferState
	downloadDir     string
	chunkSize       int
	logger          interfaces.Logger
	progressMgr     *ui.MultiProgressManager
}

// NewTransferManager creates a new transfer manager
func NewTransferManager(downloadDir string, logger interfaces.Logger) *TransferManager {
	return &TransferManager{
		activeTransfers: make(map[string]*TransferState),
		downloadDir:     downloadDir,
		chunkSize:       64 * 1024, // 64KB chunks
		logger:          logger,
		progressMgr:     ui.NewMultiProgressManager(),
	}
}

// SendFile initiates a file transfer to a peer
func (tm *TransferManager) SendFile(ctx context.Context, peerID, filePath string) error {
	// Open and validate file
	file, err := os.Open(filePath)
	if err != nil {
		return errors.NewFileTransferError("failed to open file", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return errors.NewFileTransferError("failed to get file info", err)
	}

	// Calculate file hash
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return errors.NewFileTransferError("failed to calculate file hash", err)
	}
	fileHash := hex.EncodeToString(hash.Sum(nil))

	// Reset file pointer
	if _, err := file.Seek(0, 0); err != nil {
		return errors.NewFileTransferError("failed to reset file pointer", err)
	}

	// Generate transfer ID
	transferID := fmt.Sprintf("%s_%d", peerID, time.Now().Unix())

	// Create transfer state
	transferState := &TransferState{
		TransferID:       transferID,
		FileName:         filepath.Base(filePath),
		FileSize:         fileInfo.Size(),
		Status:           "active",
		PeerID:           peerID,
		StartedAt:        time.Now(),
		FileHash:         fileHash,
		BytesTransferred: 0,
	}

	tm.mu.Lock()
	tm.activeTransfers[transferID] = transferState
	tm.mu.Unlock()

	// Add progress tracking
	progressTitle := fmt.Sprintf("Sending %s", filepath.Base(filePath))
	tm.progressMgr.AddProgress(transferID, progressTitle, fileInfo.Size())

	tm.logger.Info("File transfer started", "transfer_id", transferID, "file", filePath, "peer", peerID)

	// For now, just log the transfer initiation
	// In a full implementation, this would send chunks over the network
	tm.logger.Info("File transfer simulation completed", "transfer_id", transferID)
	transferState.Status = "completed"
	transferState.CompletedAt = time.Now()
	transferState.BytesTransferred = fileInfo.Size()

	// Finish progress tracking
	tm.progressMgr.FinishProgress(transferID)

	return nil
}

// HandleTransferMessage processes incoming file transfer messages
func (tm *TransferManager) HandleTransferMessage(peerID string, msg *FileTransferMessage) error {
	tm.logger.Debug("Handling transfer message", "type", msg.Type, "transfer_id", msg.TransferID, "peer", peerID)

	switch msg.Type {
	case "start":
		return tm.handleTransferStart(peerID, msg)
	case "chunk":
		return tm.handleChunk(peerID, msg)
	case "complete":
		return tm.handleTransferComplete(peerID, msg)
	default:
		return errors.NewFileTransferError("unknown message type", nil)
	}
}

// handleTransferStart processes the start of a file transfer
func (tm *TransferManager) handleTransferStart(peerID string, msg *FileTransferMessage) error {
	tm.logger.Info("Receiving file transfer", "transfer_id", msg.TransferID, "file", msg.FileName, "size", msg.FileSize)

	// Create transfer state
	transferState := &TransferState{
		TransferID:       msg.TransferID,
		FileName:         msg.FileName,
		FileSize:         msg.FileSize,
		Status:           "active",
		PeerID:           peerID,
		StartedAt:        time.Now(),
		ReceivedChunks:   make(map[int][]byte),
		BytesTransferred: 0,
	}

	tm.mu.Lock()
	tm.activeTransfers[msg.TransferID] = transferState
	tm.mu.Unlock()

	// Add progress tracking for download
	progressTitle := fmt.Sprintf("Receiving %s", msg.FileName)
	tm.progressMgr.AddProgress(msg.TransferID, progressTitle, msg.FileSize)

	return nil
}

// handleChunk processes a file chunk
func (tm *TransferManager) handleChunk(peerID string, msg *FileTransferMessage) error {
	tm.mu.Lock()
	transferState, exists := tm.activeTransfers[msg.TransferID]
	tm.mu.Unlock()

	if !exists {
		return errors.NewFileTransferError("transfer not found", nil)
	}

	// Store chunk
	transferState.ReceivedChunks[msg.ChunkIndex] = msg.Data
	transferState.BytesTransferred += int64(len(msg.Data))

	// Update progress bar
	tm.progressMgr.UpdateProgress(msg.TransferID, transferState.BytesTransferred)

	tm.logger.Debug("Received chunk", "transfer_id", msg.TransferID, "chunk", msg.ChunkIndex, "size", len(msg.Data))

	return nil
}

// handleTransferComplete processes transfer completion
func (tm *TransferManager) handleTransferComplete(peerID string, msg *FileTransferMessage) error {
	tm.mu.Lock()
	transferState, exists := tm.activeTransfers[msg.TransferID]
	tm.mu.Unlock()

	if !exists {
		return errors.NewFileTransferError("transfer not found", nil)
	}

	// Write file to disk
	filePath := filepath.Join(tm.downloadDir, transferState.FileName)
	file, err := os.Create(filePath)
	if err != nil {
		return errors.NewFileTransferError("failed to create file", err)
	}
	defer file.Close()

	// Write chunks in order
	for i := 0; i < len(transferState.ReceivedChunks); i++ {
		if chunk, exists := transferState.ReceivedChunks[i]; exists {
			if _, err := file.Write(chunk); err != nil {
				return errors.NewFileTransferError("failed to write chunk", err)
			}
		}
	}

	transferState.Status = "completed"
	transferState.CompletedAt = time.Now()

	tm.logger.Info("File transfer completed successfully", "transfer_id", transferState.TransferID, "file_path", filePath)

	// Finish progress tracking
	tm.progressMgr.FinishProgress(transferState.TransferID)

	delete(tm.activeTransfers, transferState.TransferID)

	return nil
}

// GetActiveTransfers returns all active transfers
func (tm *TransferManager) GetActiveTransfers() []*TransferState {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	transfers := make([]*TransferState, 0, len(tm.activeTransfers))
	for _, transfer := range tm.activeTransfers {
		transfers = append(transfers, transfer)
	}

	return transfers
}

// GetTransfer returns a specific transfer by ID
func (tm *TransferManager) GetTransfer(transferID string) (*TransferState, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	transfer, exists := tm.activeTransfers[transferID]
	return transfer, exists
}

// CancelTransfer cancels an active transfer
func (tm *TransferManager) CancelTransfer(transferID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	transfer, exists := tm.activeTransfers[transferID]
	if !exists {
		return errors.NewFileTransferError("transfer not found", nil)
	}

	transfer.Status = "cancelled"
	tm.progressMgr.RemoveProgress(transferID)
	delete(tm.activeTransfers, transferID)

	tm.logger.Info("File transfer cancelled", "transfer_id", transferID)
	return nil
}
