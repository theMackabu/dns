package cache

import (
	"container/list"
	"encoding/gob"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type CacheEntry struct {
	Key       string
	Response  *dns.Msg
	ExpiresAt time.Time
	element   *list.Element
}

type SerializableCacheEntry struct {
	Key       string
	Response  *dns.Msg
	ExpiresAt time.Time
}

type Cache interface {
	Get(key string) (*dns.Msg, bool)
	Set(key string, response *dns.Msg, ttl time.Duration)
	Delete(key string)
	Clear()
	Size() int
	DumpToFile(filename string) error
	LoadFromFile(filename string) error
}

type LRUCache struct {
	mu          sync.RWMutex
	capacity    int
	items       map[string]*CacheEntry
	evictList   *list.List
	defaultTTL  time.Duration
	stopCleanup chan struct{}
}

func NewLRUCache(capacity int, defaultTTL, cleanupInterval time.Duration) *LRUCache {
	cache := &LRUCache{
		capacity:    capacity,
		items:       make(map[string]*CacheEntry),
		evictList:   list.New(),
		defaultTTL:  defaultTTL,
		stopCleanup: make(chan struct{}),
	}

	go cache.cleanupExpired(cleanupInterval)
	return cache
}

func (c *LRUCache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	entry, exists := c.items[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		c.Delete(key)
		return nil, false
	}

	c.mu.Lock()
	c.evictList.MoveToFront(entry.element)
	c.mu.Unlock()

	return entry.Response.Copy(), true
}

func (c *LRUCache) Set(key string, response *dns.Msg, ttl time.Duration) {
	if ttl == 0 {
		ttl = c.defaultTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.items[key]; exists {
		entry.Response = response.Copy()
		entry.ExpiresAt = time.Now().Add(ttl)
		c.evictList.MoveToFront(entry.element)
		return
	}

	if c.evictList.Len() >= c.capacity {
		c.removeOldest()
	}

	entry := &CacheEntry{
		Key:       key,
		Response:  response.Copy(),
		ExpiresAt: time.Now().Add(ttl),
	}

	entry.element = c.evictList.PushFront(entry)
	c.items[key] = entry
}

func (c *LRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.items[key]; exists {
		c.evictList.Remove(entry.element)
		delete(c.items, key)
	}
}

func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*CacheEntry)
	c.evictList.Init()
}

func (c *LRUCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *LRUCache) Close() {
	close(c.stopCleanup)
}

func (c *LRUCache) removeOldest() {
	element := c.evictList.Back()
	if element != nil {
		entry := element.Value.(*CacheEntry)
		c.evictList.Remove(element)
		delete(c.items, entry.Key)
	}
}

func (c *LRUCache) cleanupExpired(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.removeExpired()
		case <-c.stopCleanup:
			return
		}
	}
}

func (c *LRUCache) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var toRemove []*list.Element

	for element := c.evictList.Back(); element != nil; element = element.Prev() {
		entry := element.Value.(*CacheEntry)
		if now.After(entry.ExpiresAt) {
			toRemove = append(toRemove, element)
		}
	}

	for _, element := range toRemove {
		entry := element.Value.(*CacheEntry)
		c.evictList.Remove(element)
		delete(c.items, entry.Key)
	}
}

func (c *LRUCache) DumpToFile(filename string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)

	var entries []SerializableCacheEntry
	now := time.Now()

	for _, entry := range c.items {
		if now.Before(entry.ExpiresAt) {
			entries = append(entries, SerializableCacheEntry{
				Key:       entry.Key,
				Response:  entry.Response,
				ExpiresAt: entry.ExpiresAt,
			})
		}
	}

	return encoder.Encode(entries)
}

func (c *LRUCache) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := gob.NewDecoder(file)
	var entries []SerializableCacheEntry

	if err := decoder.Decode(&entries); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for _, entry := range entries {
		if now.Before(entry.ExpiresAt) {
			if c.evictList.Len() >= c.capacity {
				c.removeOldest()
			}

			cacheEntry := &CacheEntry{
				Key:       entry.Key,
				Response:  entry.Response,
				ExpiresAt: entry.ExpiresAt,
			}

			cacheEntry.element = c.evictList.PushFront(cacheEntry)
			c.items[entry.Key] = cacheEntry
		}
	}

	return nil
}

func GenerateCacheKey(question dns.Question) string {
	return question.Name + ":" + dns.TypeToString[question.Qtype] + ":" + dns.ClassToString[question.Qclass]
}
