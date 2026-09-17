package db

import (
	"time"

	"github.com/newsand/base-login/internal/logger"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

var gormDB *gorm.DB

func Init(databaseURL string) error {
	config := &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	}

	var err error
	gormDB, err = gorm.Open(postgres.Open(databaseURL), config)
	if err != nil {
		return err
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		return err
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(30 * time.Minute)

	if err := sqlDB.Ping(); err != nil {
		return err
	}

	logger.Info("Database connection established")
	return nil
}

func DB() *gorm.DB {
	return gormDB
}

func Close() {
	if gormDB != nil {
		sqlDB, _ := gormDB.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
		logger.Info("Database connection closed")
	}
}

func HealthCheck() error {
	sqlDB, err := gormDB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}
