use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use crate::telemetry::TelemetryEvent;

struct Node<K, V> {
    key: K,
    value: V,
    prev: Option<Weak<Mutex<Node<K, V>>>>,
    next: Option<Arc<Mutex<Node<K, V>>>>,
}

impl<K, V> Node<K, V> {
    fn new(key: K, value: V) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            key,
            value,
            prev: None,
            next: None,
        }))
    }
}

pub struct LRUCache<K, V>
where
    K: Eq + Hash + Clone,
{
    capacity: usize,
    map: HashMap<K, Arc<Mutex<Node<K, V>>>>,
    head: Option<Arc<Mutex<Node<K, V>>>>,
    tail: Option<Arc<Mutex<Node<K, V>>>>,
}

impl<K, V> LRUCache<K, V>
where
    K: Eq + Hash + Clone,
{
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "Cache capacity must be greater than 0");

        Self {
            capacity,
            map: HashMap::new(),
            head: None,
            tail: None,
        }
    }

    /// Insert or update a value.
    ///
    /// The inserted/updated node becomes the most recently used node.
    pub fn set(&mut self, key: K, value: V) {
        // Existing key
        if let Some(node) = self.map.get(&key).cloned() {
            node.lock().unwrap().value = value;

            self.detach(&node);
            self.attach(node);

            return;
        }

        // Remove LRU item if we're at capacity.
        if self.map.len() >= self.capacity {
            if let Some(lru_key) = self
                .tail
                .as_ref()
                .map(|node| node.lock().unwrap().key.clone())
            {
                self.remove(&lru_key);
            }
        }

        // Create new node.
        let node = Node::new(key.clone(), value);

        self.map.insert(key, node.clone());
        self.attach(node);
    }

    /// Get a value and mark it as most recently used.
    pub fn get(&mut self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let node = self.map.get(key).cloned()?;

        let value = node.lock().unwrap().value.clone();

        self.detach(&node);
        self.attach(node);

        Some(value)
    }

    /// Remove a value from the cache.
    pub fn remove(&mut self, key: &K) -> bool {
    let Some(node) = self.map.remove(key) else {
        return false;
    };

    self.detach(&node);
    true
}

    /// Remove a node from the linked list.
    fn detach(&mut self, node: &Arc<Mutex<Node<K, V>>>) {
        let (prev, next) = {
            let mut node_guard = node.lock().unwrap();

            (
                node_guard.prev.take(),
                node_guard.next.take(),
            )
        };

        match (prev, next) {
            // Only node in the list.
            (None, None) => {
                self.head = None;
                self.tail = None;
            }

            // Node is the head.
            (None, Some(next)) => {
                next.lock().unwrap().prev = None;
                self.head = Some(next);
            }

            // Node is the tail.
            (Some(prev), None) => {
                if let Some(prev) = prev.upgrade() {
                    prev.lock().unwrap().next = None;
                    self.tail = Some(prev);
                } else {
                    self.tail = None;
                }
            }

            // Node is in the middle.
            (Some(prev), Some(next)) => {
                if let Some(prev) = prev.upgrade() {
                    prev.lock().unwrap().next = Some(next.clone());
                    next.lock().unwrap().prev = Some(Arc::downgrade(&prev));
                }
            }
        }
    }

    /// Attach a node to the front of the list.
    ///
    /// The head is the most recently used node.
    fn attach(&mut self, node: Arc<Mutex<Node<K, V>>>) {
        match self.head.take() {
            Some(old_head) => {
                {
                    let mut node_guard = node.lock().unwrap();
                    node_guard.prev = None;
                    node_guard.next = Some(old_head.clone());
                }

                old_head.lock().unwrap().prev = Some(Arc::downgrade(&node));

                self.head = Some(node);
            }

            None => {
                // List was empty.
                {
                    let mut node_guard = node.lock().unwrap();
                    node_guard.prev = None;
                    node_guard.next = None;
                }

                self.head = Some(node.clone());
                self.tail = Some(node);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

const CAPACITY: usize = 100;

pub static EVENTS_CACHE: LazyLock<Mutex<LRUCache<u64, TelemetryEvent>>> =
    LazyLock::new(|| Mutex::new(LRUCache::new(CAPACITY)));



pub fn cache_event(key: u64, event: TelemetryEvent) {
    EVENTS_CACHE
        .lock()
        .unwrap()
        .set(key, event);
}

pub fn get_cached_event(key: u64) -> Option<TelemetryEvent> {
    EVENTS_CACHE
        .lock()
        .unwrap()
        .get(&key)
}

// fn main() {
//     let mut cache = LRUCache::new(2);
//     cache.set("key1", "value1");
//     cache.set("key2", "value2");
//     println!("Retrieved: {:?}", cache.get(&"key1")); // Access key1, making it most recently used
//     cache.set("key3", "value3"); // Should evict key2 as it is the least recently used
//     match cache.get(&"key2") {
//         Some(value) => println!("Retrieved: {:?}", value),
//         None => println!("Key2 was evicted"), // Expected outcome
//     }
//     // Verify key3 is in the cache
//     match cache.get(&"key3") {
//         Some(value) => println!("Key3 is in cache with value: {:?}", value),
//         None => println!("Key3 is not in cache (unexpected)"),
//     }
// }