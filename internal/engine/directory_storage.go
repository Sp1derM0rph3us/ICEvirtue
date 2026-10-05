package engine

import "github.com/Sp1derM0rph3us/ICEvirtue/internal/models"

func (run *runner) storeDirectoryBatch(p *models.Profile, rows []models.DirectoryFinding) (int, error) {
	n, e := run.diffDirectories(&p.ID, rows)
	if e != nil {
		run.rememberStorageError(e)
	}
	return n, e
}
