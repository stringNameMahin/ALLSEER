package daemon

import (
	"sync"

	"github.com/stringNameMahin/ALLSEER/pkg/decision"
)

// hub fans decisions out to stream subscribers. A subscriber that falls behind
// is dropped: the stream drops, the pipeline does not.
type hub struct {
	mu   sync.Mutex
	next int
	subs map[int]*subscriber
}

type subscriber struct {
	ch     chan decision.Decision
	accept func(decision.Decision) bool
	closed bool
}

func newHub() *hub { return &hub{subs: map[int]*subscriber{}} }

func (h *hub) subscribe(accept func(decision.Decision) bool) (int, <-chan decision.Decision) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	s := &subscriber{ch: make(chan decision.Decision, 1024), accept: accept}
	h.subs[h.next] = s
	return h.next, s.ch
}

func (h *hub) unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.subs[id]; ok {
		delete(h.subs, id)
		if !s.closed {
			s.closed = true
			close(s.ch)
		}
	}
}

func (h *hub) publish(d decision.Decision) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, s := range h.subs {
		if !s.accept(d) {
			continue
		}
		select {
		case s.ch <- d:
		default:
			delete(h.subs, id)
			s.closed = true
			close(s.ch)
		}
	}
}

func (h *hub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, s := range h.subs {
		delete(h.subs, id)
		if !s.closed {
			s.closed = true
			close(s.ch)
		}
	}
}
