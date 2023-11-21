use array::Array;
use starknet::{ ContractAddress,    SyscallResult, storage_access::StorageAddress, class_hash::ClassHash};

#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
struct Timestamp {
    block_number: u256,
    block_timestamp: u256
}


#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
struct GeneralPolicy {
    contract_address: ContractAddress, // nul means any contract
    selector: felt252, // 0 means all methods
    max_calls_allowed: u256   
}

#[derive(Drop, Serde, PartialEq)]
struct DappSession {
    invoker:ContractAddress,
    valid_from: Timestamp,
    valid_to: Timestamp,
    policies: Array<GeneralPolicy> 
}

#[event]
#[derive(Drop, starknet::Event)]
enum Event {
    PermissionGranted: PermissionGranted,
    PermissionRevoked: PermissionRevoked,
}

#[derive(Drop, starknet::Event)]
struct PermissionGranted {
    #[key]
    dapp_invoker: ContractAddress,
    valid_from: Timestamp,
    valid_to: Timestamp,
    policies:Array<GeneralPolicy>,
}

#[derive(Drop, starknet::Event)]
struct PermissionRevoked {
    #[key]
    dapp_invoker: ContractAddress,
    revoked_policies:Array<GeneralPolicy>,
}


#[starknet::interface]
trait IDappSessionHandler<TContractState> {
    fn grant_permissions(ref self:TContractState, session:DappSession); // only called by user
    fn revoke_permissions(ref self:TContractState, session:DappSession); // called by user or session dapp in case of 
    fn revoke_all(ref self:TContractState, session:DappSession); // called by user
    fn is_policy_active(self:@TContractState, dapp_representetive:ContractAddress, call_address:ContractAddress, selector:felt252)->bool;
    fn execute_dapp_call(ref self:TContractState, selector:felt252, calldata: Array<felt252>)->SyscallResult<Span<felt252>>;
}





//  storage
//  policy_nonce,
//  revoke_all_policies by nonce
//  revoke_policies specific

//  invoker -> contract_address -> selectors, valid from, valid_to,
//  nonce
// ( invoker,contract_address,selector) -> valid_from, valid_to,  


// apply policy on user behalf
// apply policy directly
// remove policy user can invoke
// 


// #[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
// struct Policy {
//     contract_address: ContractAddress,
//     selector: u256,
//     valid_from: Timestamp,
//     valid_to: Timestamp,
//     payment_amount: u256, // amount paid for Subscription
//     payment_token: ContractAddress, // in what token paid for Subscription
//     sub_period_in_seconds: u256, // duration of subscription in sec
//     sub_id: u256, // identifier of subscription, user can have several diff subscription for specific service
//     max_periods_allowed: u256 // service specify how much periods one can use
// }


