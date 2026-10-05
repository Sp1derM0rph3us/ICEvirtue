package models

import "time"

const ModularitySchema = "2026_10_modularity_v1"

type ScanRun struct {
	NewFindings int        `json:"new_findings"`
	ID          string     `gorm:"primaryKey" json:"id"`
	ProfileID   string     `gorm:"index" json:"profile_id"`
	Domain      string     `json:"domain"`
	Source      string     `json:"source"`
	Revision    uint64     `json:"revision"`
	Status      string     `gorm:"index" json:"status"`
	Summary     string     `json:"summary"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `gorm:"index" json:"finished_at"`
}
type ScanStageRun struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	RunID          string     `gorm:"index" json:"run_id"`
	Name           string     `json:"name"`
	Status         string     `json:"status"`
	InputCount     int        `json:"input_count"`
	OutputCount    int        `json:"output_count"`
	PersistedCount int        `json:"persisted_count"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at"`
	Summary        string     `json:"summary"`
}
type ScanToolRun struct {
	Scope       string    `json:"scope"`
	ID          uint      `gorm:"primaryKey" json:"id"`
	StageID     uint      `gorm:"index" json:"stage_id"`
	RunID       string    `gorm:"index" json:"run_id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	OutputCount int       `json:"output_count"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	Summary     string    `json:"summary"`
}
type WorkerHeartbeat struct {
	ID       string `gorm:"primaryKey" json:"id"`
	LastSeen int64  `gorm:"index" json:"last_seen"`
}
type SchedulerLease struct {
	ID         uint `gorm:"primaryKey"`
	Owner      string
	Token      string
	LeaseUntil int64
}
type OutboxEvent struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	Type      string    `json:"type"`
	ProfileID string    `json:"profile_id"`
	Data      string    `json:"data"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}
