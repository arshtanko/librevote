package gossip

import (
	"context"
	"fmt"
	"sync"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
)

// TopicName returns the standard GossipSub topic for a network.
func TopicName(networkID string) string {
	return fmt.Sprintf("librevote.%s.objects.v1", networkID)
}

// HostInterface is the minimal host interface needed by the GossipSub service.
type HostInterface interface {
	ID() string
}

// AnnouncementCallback is called when a new announcement is received.
// The callback receives the announcement; the full object must be fetched
// through a separate path (e.g. HTTP sync transport). The call should not
// mark the announced object as valid.
// Return nil on success; a non-nil error prevents the object_id from being
// marked as seen and allows future re-delivery attempts.
type AnnouncementCallback func(announcement ObjectAnnouncement, sourcePeerID string) error

// Service manages a GossipSub topic for object announcements.
type Service struct {
	topic    *pubsub.Topic
	sub      *pubsub.Subscription
	callback AnnouncementCallback
	seenIDs  map[string]struct{}
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewService creates a GossipSub service on the given libp2p host.
func NewService(ctx context.Context, h host.Host, networkID string, callback AnnouncementCallback) (*Service, error) {
	if h == nil {
		return nil, fmt.Errorf("host is required")
	}
	if networkID == "" {
		return nil, fmt.Errorf("network_id is required")
	}

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("create gossipsub: %w", err)
	}

	topicName := TopicName(networkID)
	topic, err := ps.Join(topicName)
	if err != nil {
		return nil, fmt.Errorf("join topic %s: %w", topicName, err)
	}

	sub, err := topic.Subscribe()
	if err != nil {
		return nil, fmt.Errorf("subscribe topic %s: %w", topicName, err)
	}

	svcCtx, cancel := context.WithCancel(ctx)
	svc := &Service{
		topic:    topic,
		sub:      sub,
		callback: callback,
		seenIDs:  make(map[string]struct{}),
		ctx:      svcCtx,
		cancel:   cancel,
	}

	if callback != nil {
		go svc.subscriptionLoop(svcCtx)
	}

	return svc, nil
}

// Publish encodes and publishes an announcement to the GossipSub topic.
func (s *Service) Publish(ctx context.Context, a ObjectAnnouncement) error {
	if s == nil || s.topic == nil {
		return fmt.Errorf("gossip service not initialized")
	}
	data, err := EncodeAnnouncement(a)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	if err := s.topic.Publish(ctx, data); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}

// Close shuts down the subscription loop and cancels the context.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	if s.sub != nil {
		s.sub.Cancel()
	}
	if s.topic != nil {
		return s.topic.Close()
	}
	return nil
}

// IsDuplicate reports whether the object_id has been seen before.
func (s *Service) IsDuplicate(objectID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seenIDs[objectID]
	return ok
}

// MarkSeen records an object_id as seen for duplicate suppression.
func (s *Service) MarkSeen(objectID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seenIDs[objectID] = struct{}{}
}

// ForgetSeen removes an object_id from the seen set so that a future
// announcement can be re-delivered. Use this to allow refetch after a
// previously successful callback payload was evicted or needs re-acquisition.
func (s *Service) ForgetSeen(objectID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seenIDs, objectID)
}

func (s *Service) subscriptionLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := s.sub.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		a, err := DecodeAnnouncement(msg.Data)
		if err != nil {
			continue
		}

		sourcePeerID := msg.ReceivedFrom.String()

		s.mu.Lock()
		if _, ok := s.seenIDs[a.ObjectID]; ok {
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()

		if s.callback != nil {
			if err := s.callback(a, sourcePeerID); err != nil {
				continue
			}
		}

		s.MarkSeen(a.ObjectID)
	}
}
