package repository

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// NewDB opens a GORM/Postgres connection pool for the given DSN.
func NewDB(dsn string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

// AutoMigrate creates/updates tables for the current build stage's schema.
// golang-migrate takes over as the schema evolves (see
// docs/TECHNICAL_DESIGN.md); AutoMigrate is a stopgap until then.
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&userModel{}, &tenantModel{}, &membershipModel{})
}
