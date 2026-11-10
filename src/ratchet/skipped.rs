use crate::ratchet::chain::MessageKey;
use std::collections::{BTreeMap, VecDeque};
use zeroize::Zeroize;

/// Maximum number of skipped message keys retained across all chains.
///
/// `max_skip` only bounds how many keys a single out-of-order jump may
/// generate; keys for messages that never arrive would otherwise accumulate
/// across chains without bound (and get re-serialized into every session blob).
pub(crate) const MAX_SKIPPED_MESSAGE_KEYS: usize = 2000;

/// The skipped message keys of one receiving chain, all of which share that
/// chain's header key.
#[derive(Clone)]
struct SkippedChain {
    header_key: Box<[u8; 32]>,
    keys: BTreeMap<u32, MessageKey>,
}

impl Drop for SkippedChain {
    fn drop(&mut self) {
        self.header_key.zeroize();
    }
}

/// Message keys for messages that were skipped over and may still arrive.
///
/// Keys are grouped by the header key of the receiving chain they belong to.
///
/// Chains are held oldest first. A chain only ever gains keys while it is the
/// current receiving chain, and it gains them in increasing message-number
/// order, so "oldest chain, lowest message number" is exactly the order in
/// which the keys were stored. Eviction and serialization both rely on that.
#[derive(Clone, Default)]
pub(crate) struct SkippedKeys {
    chains: VecDeque<SkippedChain>,
    len: usize,
}

impl SkippedKeys {
    /// Total number of stored message keys.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// The header key of every chain with keys outstanding, oldest first,
    /// alongside the index to pass to [`Self::get`] and [`Self::remove`].
    pub(crate) fn header_keys(&self) -> impl Iterator<Item = (usize, &[u8; 32])> {
        self.chains
            .iter()
            .enumerate()
            .map(|(index, chain)| (index, chain.header_key.as_ref()))
    }

    /// Index of the chain stored under `header_key`, if it has keys outstanding.
    pub(crate) fn position(&self, header_key: &[u8; 32]) -> Option<usize> {
        // The most recent chain is by far the likeliest match.
        self.chains
            .iter()
            .rposition(|chain| chain.header_key.as_ref() == header_key)
    }

    pub(crate) fn get(&self, chain: usize, message_number: u32) -> Option<&MessageKey> {
        self.chains.get(chain)?.keys.get(&message_number)
    }

    /// Removes a key once its message has been decrypted. Indices returned by
    /// [`Self::position`] and [`Self::header_keys`] are invalidated.
    pub(crate) fn remove(&mut self, chain: usize, message_number: u32) {
        let Some(entry) = self.chains.get_mut(chain) else {
            return;
        };
        if entry.keys.remove(&message_number).is_some() {
            self.len -= 1;
        }
        if entry.keys.is_empty() {
            self.chains.remove(chain);
        }
    }

    /// Stores a skipped message key, evicting the oldest keys once the store
    /// holds [`MAX_SKIPPED_MESSAGE_KEYS`].
    pub(crate) fn insert(&mut self, header_key: &[u8; 32], message_number: u32, key: MessageKey) {
        while self.len >= MAX_SKIPPED_MESSAGE_KEYS {
            if !self.evict_oldest() {
                break;
            }
        }

        let index = match self.position(header_key) {
            Some(index) => index,
            None => {
                self.chains.push_back(SkippedChain {
                    header_key: Box::new(*header_key),
                    keys: BTreeMap::new(),
                });
                self.chains.len() - 1
            }
        };

        if let Some(chain) = self.chains.get_mut(index)
            && chain.keys.insert(message_number, key).is_none()
        {
            self.len += 1;
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let Some(oldest) = self.chains.front_mut() else {
            return false;
        };
        let evicted = oldest.keys.pop_first().is_some();
        if evicted {
            self.len -= 1;
        }
        if oldest.keys.is_empty() {
            self.chains.pop_front();
        }
        evicted
    }

    /// Every stored key as `(header_key, message_number, message_key)`, in the
    /// order the keys were stored.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8; 32], u32, &MessageKey)> {
        self.chains.iter().flat_map(|chain| {
            chain
                .keys
                .iter()
                .map(|(number, key)| (chain.header_key.as_ref(), *number, key))
        })
    }

    /// Drops every stored key. Header keys and message keys wipe themselves.
    pub(crate) fn clear(&mut self) {
        self.chains.clear();
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> MessageKey {
        MessageKey::from(Box::new([byte; 32]))
    }

    #[test]
    fn test_keys_are_grouped_by_header_key() {
        let mut store = SkippedKeys::default();
        store.insert(&[1; 32], 0, key(10));
        store.insert(&[1; 32], 1, key(11));
        store.insert(&[2; 32], 0, key(20));

        assert_eq!(store.len(), 3);
        assert_eq!(store.header_keys().count(), 2);

        let first = store.position(&[1; 32]).unwrap();
        assert_eq!(store.get(first, 1).unwrap().as_bytes(), &[11; 32]);
        assert!(store.get(first, 2).is_none());
        assert!(store.position(&[3; 32]).is_none());
    }

    #[test]
    fn test_removing_the_last_key_drops_the_chain() {
        let mut store = SkippedKeys::default();
        store.insert(&[1; 32], 0, key(10));
        store.insert(&[2; 32], 0, key(20));

        let first = store.position(&[1; 32]).unwrap();
        store.remove(first, 0);

        assert_eq!(store.len(), 1);
        assert!(store.position(&[1; 32]).is_none());
        assert!(store.position(&[2; 32]).is_some());
    }

    #[test]
    fn test_reinserting_a_key_does_not_change_the_count() {
        let mut store = SkippedKeys::default();
        store.insert(&[1; 32], 0, key(10));
        store.insert(&[1; 32], 0, key(99));

        assert_eq!(store.len(), 1);
        let chain = store.position(&[1; 32]).unwrap();
        assert_eq!(store.get(chain, 0).unwrap().as_bytes(), &[99; 32]);
    }

    #[test]
    fn test_eviction_removes_the_oldest_keys_first() {
        let mut store = SkippedKeys::default();
        store.insert(&[1; 32], 7, key(1));
        for number in 0..MAX_SKIPPED_MESSAGE_KEYS as u32 {
            store.insert(&[2; 32], number, key(2));
        }

        // The single key of the older chain went first, and the chain with it.
        assert_eq!(store.len(), MAX_SKIPPED_MESSAGE_KEYS);
        assert!(store.position(&[1; 32]).is_none());

        store.insert(&[3; 32], 0, key(3));
        let second = store.position(&[2; 32]).unwrap();
        assert_eq!(store.len(), MAX_SKIPPED_MESSAGE_KEYS);
        assert!(store.get(second, 0).is_none());
        assert!(store.get(second, 1).is_some());
    }

    #[test]
    fn test_iteration_follows_storage_order() {
        let mut store = SkippedKeys::default();
        store.insert(&[1; 32], 4, key(1));
        store.insert(&[1; 32], 5, key(1));
        store.insert(&[2; 32], 0, key(2));

        let order: Vec<_> = store.iter().map(|(hk, n, _)| (hk[0], n)).collect();
        assert_eq!(order, vec![(1, 4), (1, 5), (2, 0)]);
    }
}
