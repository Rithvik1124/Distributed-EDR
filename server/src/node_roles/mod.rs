pub mod ioc;
pub mod sigma;
pub mod yara;
pub mod consensus;
pub mod transport;
use std::{ sync::{Arc, LazyLock, RwLock}};
use lru::LruCache;
//CACHING

pub static CACHE: LazyLock<Arc<RwLock<LruCache<String, String>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(LruCache::unbounded())));


