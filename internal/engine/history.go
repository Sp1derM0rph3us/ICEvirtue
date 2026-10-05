package engine

import (
	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
	"gorm.io/gorm"
	"time"
)

func (run *runner) beginStage(name string, input int) error {
	if run.job.ID == 0 {
		return nil
	}
	row := models.ScanStageRun{RunID: run.job.RunID, Name: name, InputCount: input, Status: "running", StartedAt: time.Now().UTC()}
	e := run.write(func(tx *gorm.DB) error { return tx.Create(&row).Error })
	run.stageID = row.ID
	return e
}
func (run *runner) endStage(report *stageReport, stored int, storageErr error) error {
	if run.job.ID == 0 {
		return nil
	}
	return run.write(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		status, summary := "ok", ""
		if report.attempted() == 0 {
			status = "skipped"
		}
		if report.failed() > 0 {
			status = "failed"
			if report.Unique > 0 {
				status = "partial"
			}
			summary = "one or more tools failed"
		}
		if storageErr != nil {
			status = "failed"
			summary = "storage failed; only committed batches retained"
		}
		if e := tx.Model(&models.ScanStageRun{}).Where("id=?", run.stageID).Updates(map[string]any{"status": status, "summary": summary, "output_count": report.Unique, "persisted_count": stored, "finished_at": now}).Error; e != nil {
			return e
		}
		for _, r := range report.runs {
			state, note := "ok", ""
			if r.skipped() {
				state = "skipped"
				note = r.SkipReason
			} else if r.Err != nil {
				state = "failed"
				if r.Count > 0 {
					state = "partial"
				}
				note = "tool failed, timed out, or returned incomplete output"
			}
			// Tool names and skip reasons are application constants; raw errors are excluded.
			row := models.ScanToolRun{Scope: "result", RunID: run.job.RunID, StageID: run.stageID, Name: r.Tool, Status: state, Summary: note, OutputCount: r.Count, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt}
			if e := tx.Create(&row).Error; e != nil {
				return e
			}
		}
		return nil
	})
}

// Execution rows survive a killed worker; result rows separately describe decoded adapter output.
func (run *runner) beginTool(name string) (uint, error) {
	if run.job.ID == 0 {
		return 0, nil
	}
	row := models.ScanToolRun{Scope: "execution", RunID: run.job.RunID, StageID: run.stageID, Name: name, Status: "running", StartedAt: time.Now().UTC()}
	e := run.write(func(tx *gorm.DB) error { return tx.Create(&row).Error })
	return row.ID, e
}
func (run *runner) endTool(id uint, toolErr error) error {
	if id == 0 {
		return nil
	}
	status, summary := "completed", ""
	if toolErr != nil {
		status = "failed"
		summary = "process failed, timed out, or was canceled"
	}
	return run.write(func(tx *gorm.DB) error {
		return tx.Model(&models.ScanToolRun{}).Where("id=?", id).Updates(map[string]any{"status": status, "summary": summary, "finished_at": time.Now().UTC()}).Error
	})
}
