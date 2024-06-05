package apiutil

import "github.com/go-chi/chi/v5"

// ChiController is an interface for Chi controllers.
type ChiController interface {
	Routes() *chi.Mux
}
