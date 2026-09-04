package main

import (
	"net/http"

	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// handleDowntimeList mirrors GET /v1/downtimes.
//
// The response is domain.DowntimeList verbatim, which is the whole point: the
// mesh's downtime source parses this server and production with one decoder, so
// a schema mistake here is a schema mistake there. Items is always a non-nil
// slice so an empty result serialises as [] rather than null.
func (s *server) handleDowntimeList(w http.ResponseWriter, r *http.Request) {
	items := s.timeline.DowntimesAt(s.clock.Now())
	s.metrics.Counter("sim_downtime_list_requests").Inc()
	s.writeJSON(w, http.StatusOK, domain.DowntimeList{
		Entity: "collection",
		Count:  len(items),
		Items:  items,
	})
}

// handleDowntimeGet mirrors GET /v1/downtimes/{id}.
//
// A notice outside its visibility window is a 404 rather than a stale entity:
// answering with a downtime the API would no longer report is how a consumer
// ends up holding an outage open forever.
func (s *server) handleDowntimeGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validRazorID("down", id) {
		s.writeError(w, http.StatusBadRequest, "BAD_REQUEST_ERROR",
			"The id provided is not a valid downtime identifier",
			"NA", "NA", "input_validation_failed", nil)
		return
	}
	entity, ok := s.timeline.DowntimeByID(id, s.clock.Now())
	if !ok {
		s.writeError(w, http.StatusNotFound, "BAD_REQUEST_ERROR",
			"The requested downtime does not exist", "NA", "NA", "input_validation_failed", nil)
		return
	}
	s.writeJSON(w, http.StatusOK, entity)
}
