use crate::*;
use near_sdk::AccountId;

#[near]
impl Contract {
    pub fn get_owner_id(&self) -> AccountId {
        self.owner_id.clone()
    }

    pub fn get_worker_len(&self) -> u32 {
        self.worker_by_account_id.len()
    }

    pub fn get_worker(&self, account_id: AccountId) -> Option<Worker> {
        self.worker_by_account_id.get(&account_id).cloned()
    }

    pub fn get_workers(&self, offset: u32, limit: u32) -> Vec<&Worker> {
        self.worker_by_account_id
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .collect()
    }

    pub fn get_pending_requests(&self, offset: u64, limit: u64) -> Vec<&Request> {
        self.pending_requests
            .values()
            .skip(offset as usize)
            .take(limit as usize)
            .collect()
    }
}
