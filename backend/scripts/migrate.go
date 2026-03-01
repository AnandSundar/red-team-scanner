// =============================================================================
// Red Team Scanner - Database Migration Runner
// Phase 3: Database Layer
// =============================================================================
// Usage:
//   go run scripts/migrate.go up
//   go run scripts/migrate.go down
//   go run scripts/migrate.go version
//   go run scripts/migrate.go force <version>
// =============================================================================

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(".env.development"); err != nil {
		// Try loading from .env if .env.development doesn't exist
		_ = godotenv.Load()
	}

	// Get database connection string
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = os.Getenv("POSTGRES_DSN")
	}
	if databaseURL == "" {
		// Default connection string for development
		host := getEnv("POSTGRES_HOST", "localhost")
		port := getEnv("POSTGRES_PORT", "5432")
		user := getEnv("POSTGRES_USER", "postgres")
		password := getEnv("POSTGRES_PASSWORD", "postgres")
		dbname := getEnv("POSTGRES_DB", "redteam")
		databaseURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			user, password, host, port, dbname)
	}

	// Parse command line arguments
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Create migration instance
	m, err := createMigrator(databaseURL)
	if err != nil {
		log.Fatalf("Failed to create migrator: %v", err)
	}
	defer m.Close()

	// Execute command
	ctx := context.Background()
	switch command {
	case "up":
		err = migrateUp(ctx, m)
	case "down":
		err = migrateDown(ctx, m)
	case "version":
		err = showVersion(m)
	case "force":
		if len(os.Args) < 3 {
			log.Fatal("Usage: migrate force <version>")
		}
		version, parseErr := strconv.Atoi(os.Args[2])
		if parseErr != nil {
			log.Fatalf("Invalid version number: %v", parseErr)
		}
		err = forceVersion(m, version)
	case "create":
		if len(os.Args) < 3 {
			log.Fatal("Usage: migrate create <name>")
		}
		err = createMigration(os.Args[2])
	case "reset":
		err = resetMigrations(ctx, m)
	case "status":
		err = showStatus(m)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
}

// createMigrator creates a new migration instance
func createMigrator(databaseURL string) (*migrate.Migrate, error) {
	// Open database connection using pgx
	db := stdlib.OpenDBFromPool(nil)
	defer db.Close()

	// Create postgres driver instance
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		// Try alternative approach with connection string
		return migrate.New(
			"file://migrations",
			databaseURL,
		)
	}

	// Create migrator with custom driver
	return migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres",
		driver,
	)
}

// migrateUp runs all pending migrations
func migrateUp(ctx context.Context, m *migrate.Migrate) error {
	fmt.Println("Running migrations up...")
	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to run - database is up to date")
			return nil
		}
		return fmt.Errorf("failed to run up migrations: %w", err)
	}

	version, dirty, err := m.Version()
	if err != nil {
		return fmt.Errorf("failed to get version: %w", err)
	}

	fmt.Printf("Migrations completed successfully. Version: %d, Dirty: %v\n", version, dirty)
	return nil
}

// migrateDown runs one migration down
func migrateDown(ctx context.Context, m *migrate.Migrate) error {
	fmt.Println("Running migration down...")
	if err := m.Steps(-1); err != nil {
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to rollback")
			return nil
		}
		return fmt.Errorf("failed to run down migration: %w", err)
	}

	version, dirty, err := m.Version()
	if err != nil {
		return fmt.Errorf("failed to get version: %w", err)
	}

	fmt.Printf("Rollback completed. Version: %d, Dirty: %v\n", version, dirty)
	return nil
}

// resetMigrations rolls back all migrations
func resetMigrations(ctx context.Context, m *migrate.Migrate) error {
	fmt.Println("Resetting all migrations...")
	if err := m.Down(); err != nil {
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to reset")
			return nil
		}
		return fmt.Errorf("failed to reset migrations: %w", err)
	}

	fmt.Println("All migrations rolled back successfully")
	return nil
}

// showVersion displays current migration version
func showVersion(m *migrate.Migrate) error {
	version, dirty, err := m.Version()
	if err != nil {
		if err == migrate.ErrNilVersion {
			fmt.Println("No migrations applied yet")
			return nil
		}
		return fmt.Errorf("failed to get version: %w", err)
	}

	fmt.Printf("Current version: %d, Dirty: %v\n", version, dirty)
	return nil
}

// forceVersion forces a specific migration version
func forceVersion(m *migrate.Migrate, version int) error {
	fmt.Printf("Forcing version to %d...\n", version)
	if err := m.Force(version); err != nil {
		return fmt.Errorf("failed to force version: %w", err)
	}

	fmt.Printf("Version forced to %d\n", version)
	return nil
}

// showStatus displays migration status
func showStatus(m *migrate.Migrate) error {
	version, dirty, err := m.Version()
	if err != nil {
		if err == migrate.ErrNilVersion {
			fmt.Println("Status: No migrations applied")
			return nil
		}
		return fmt.Errorf("failed to get version: %w", err)
	}

	fmt.Printf("Migration Status:\n")
	fmt.Printf("  Current Version: %d\n", version)
	fmt.Printf("  Dirty: %v\n", dirty)

	if dirty {
		fmt.Println("  WARNING: Database is in a dirty state. Run 'migrate force' to fix.")
	}

	return nil
}

// createMigration creates new migration files
func createMigration(name string) error {
	// Get next version number
	files, err := os.ReadDir("migrations")
	if err != nil {
		if os.IsNotExist(err) {
			// Create migrations directory
			if err := os.MkdirAll("migrations", 0755); err != nil {
				return fmt.Errorf("failed to create migrations directory: %w", err)
			}
			files = []os.DirEntry{}
		} else {
			return fmt.Errorf("failed to read migrations directory: %w", err)
		}
	}

	// Calculate next version
	maxVersion := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if len(name) < 14 {
			continue
		}
		versionStr := name[:14]
		version, err := strconv.Atoi(versionStr)
		if err == nil && version > maxVersion {
			maxVersion = version
		}
	}

	nextVersion := maxVersion + 1
	versionStr := fmt.Sprintf("%06d", nextVersion)

	// Create migration files
	upFile := fmt.Sprintf("migrations/%s_%s.up.sql", versionStr, name)
	downFile := fmt.Sprintf("migrations/%s_%s.down.sql", versionStr, name)

	// Write up migration template
	upTemplate := fmt.Sprintf(`-- Migration: %s (Up)
-- Created at: %s

BEGIN;

-- Add your up migration here

COMMIT;
`, name, time.Now().Format("2006-01-02 15:04:05"))

	if err := os.WriteFile(upFile, []byte(upTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create up migration file: %w", err)
	}

	// Write down migration template
	downTemplate := fmt.Sprintf(`-- Migration: %s (Down)
-- Created at: %s

BEGIN;

-- Add your down migration here

COMMIT;
`, name, time.Now().Format("2006-01-02 15:04:05"))

	if err := os.WriteFile(downFile, []byte(downTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create down migration file: %w", err)
	}

	fmt.Printf("Created migration files:\n")
	fmt.Printf("  %s\n", upFile)
	fmt.Printf("  %s\n", downFile)

	return nil
}

// printUsage prints usage information
func printUsage() {
	fmt.Println("Database Migration Runner")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go run scripts/migrate.go <command> [args...]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  up              Run all pending migrations")
	fmt.Println("  down            Rollback one migration")
	fmt.Println("  version         Show current migration version")
	fmt.Println("  force <version> Force a specific version")
	fmt.Println("  create <name>   Create a new migration")
	fmt.Println("  reset           Rollback all migrations")
	fmt.Println("  status          Show migration status")
}

// getEnv gets environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
