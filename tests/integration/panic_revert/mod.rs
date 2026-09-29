// SPDX-License-Identifier: Apache-2.0
use soroban_sdk::{contractimport, testutils::Ledger, Env, Symbol, Vec, panic, panic_with_hook};
use soroban_test_env::{Address, Contract, ContractError, LedgerError};

#[contractimport]
mod contract;
type ContractClient = contract::Client<Env>;

#[test]
fn test_panic_reverts_storage() {
    let env = Env::default();
    let ledger = Ledger::default();
    env.ledger().set(&ledger);
    
    let contract_id = env.register_contract(None, contract);
    let client = ContractClient::new(&env, &contract_id);
    
    // Initial state
    let initial_value = 42;
    client.set_value(&42).unwrap();
    assert_eq!(client.get_value(), initial_value);
    
    // Force panic during write
    env.panic_hook(|_| panic_with_hook("malicious proof", "test"));
    
    // Should revert to initial state
    assert_eq!(client.get_value(), initial_value);
}

#[test]
fn test_panic_isolates_memory() {
    let env = Env::default();
    let ledger = Ledger::default();
    env.ledger().set(&ledger);
    
    let contract_id = env.register_contract(None, contract);
    let client = ContractClient::new(&env, &contract_id);
    
    // Write before panic
    client.set_value(&100).unwrap();
    
    // Force panic
    env.panic_hook(|_| panic_with_hook("memory test", "test"));
    
    // Verify no residual memory
    assert!(env.memory().is_empty());
}

#[test]
fn test_nested_panic_reverts() {
    let env = Env::default();
    let ledger = Ledger::default();
    env.ledger().set(&ledger);
    
    let contract_id = env.register_contract(None, contract);
    let client = ContractClient::new(&env, &contract_id);
    
    // Initial state
    client.set_value(&200).unwrap();
    
    // Nested panic simulation
    env.panic_hook(|_| {
        panic_with_hook("outer", "test");
        panic_with_hook("inner", "test");
    });
    
    // Should revert to initial state
    assert_eq!(client.get_value(), 200);
}