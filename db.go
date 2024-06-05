package apiutil

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

func ConnectPostgres(dsn string, waitTime time.Duration) *pgxpool.Pool {
	count := 0

	for {
		pool, err := pgxpool.New(context.Background(), dsn)
		if err == nil {
			return pool
		}

		count++
		if count >= 5 {
			fmt.Println("unable to connect: ", err)
			fmt.Printf("retrying in %d ms...", waitTime.Milliseconds())
			time.Sleep(waitTime)
			count = 0
		}
	}
}
