package events

import (
	"log"
	"sync"
)

// Event represents a basic SSE message sent to the frontend
type Event struct {
	Type      string      `json:"type"`       // e.g., "profile_update", "discovery_update"
	ProfileID string      `json:"profile_id"` // stringified UUID
	Data      interface{} `json:"data,omitempty"`
}

type Broker struct {
	clients map[chan Event]bool
	mu      sync.RWMutex
}

var (
	instance *Broker
	once     sync.Once
)

// GetBroker returns the singleton event broker
func GetBroker() *Broker {
	once.Do(func() {
		instance = &Broker{
			clients: make(map[chan Event]bool),
		}
	})
	return instance
}

// Subscribe adds a new client channel to the broker
func (b *Broker) Subscribe() chan Event {
	ch := make(chan Event, 100)
	b.mu.Lock()
	b.clients[ch] = true
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a client channel from the broker
func (b *Broker) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.clients[ch]; ok {
		delete(b.clients, ch)
		close(ch)
	}
}

// Broadcast sends an event to all connected clients
func (b *Broker) Broadcast(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	for ch := range b.clients {
		select {
		case ch <- e: // Send the event
		default:
			// If the client's channel is full, they are too slow.
			log.Printf("[-] Dropping SSE event for a slow client to prevent blocking")
		}
	}
}

// Broadcast is a global helper to quickly dispatch events
func Broadcast(eventType, profileID string, data interface{}) {
	GetBroker().Broadcast(Event{
		Type:      eventType,
		ProfileID: profileID,
		Data:      data,
	})
}
