# General 

In this repository, we showcase the utilization of Account Abstraction (AA) to facilitate dApps sessions. Sessions enable decentralized applications (dApps) to independently execute transactions on behalf of users, removing the need for wallet confirmation. Users can place confidence in the fact that transactions conform to established session policies for the entire duration of the session's natural lifespan.


# Details
```
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
struct Timestamp {
    block_number: u64,
    block_time: u64
}
```
```
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
struct GeneralPolicy {
    contract_address: ContractAddress, // which contract dapp allowed to call
    selector: felt252, // which method allowed to be called by dapp of specified contract
    max_calls_allowed: u32 // how many calls allowed to be performed on behalf of user for this method of contract
}
```
```
#[derive(Drop, Serde, PartialEq)]
struct DappSession {
    invoker: ContractAddress, // dapp invoker that can execute txs on behalf of the user
    valid_from: Timestamp, // from what timestamp this session is valid 
    valid_to: Timestamp, // to what timestamp this session is valid
    request_expiry:Timestamp, // when this dapp request for issue session will expire
    policies: Span<GeneralPolicy>, // what policies user allow to grant
}
```
```
#[starknet::interface]
trait IDappSessionHandler<TContractState> {
    // Grants persmissions for dapp to execute txs on behalf of user wrt to constraints, can be executed by user itself only
    // only called by user else validate signature if, // called by session dapp invoker to avoid gas spending by user 
    fn grant_permissions(ref self: TContractState, session: DappSession, signature:(felt252,felt252)); 
    
    //  Revoke specified permissions of the dapp, can be executed either by the user itself or by the dapp in case it got compromised
    fn revoke_permissions(ref self: TContractState, session: DappSession);

    //Revoke all access for particual dapp caller, only can be invoked by user itself
    fn revoke_all(ref self: TContractState, dapp_caller: ContractAddress); 
    
    // Return if particulal policy is currently active and call can be executed by dapp_representetive
    fn is_policy_active(self: @TContractState, dapp_representetive: ContractAddress, call_address: ContractAddress, selector: felt252) -> bool;

    // Executes call wrt to constraints specified
    fn execute_dapp_call(ref self: TContractState, contract: ContractAddress, selector: felt252, calldata: Span<felt252>) -> Span<felt252>;

    fn execute_dapp_calls(ref self: TContractState, calls: Span<(ContractAddress, felt252, Span<felt252>)>) -> Array<Span<felt252>>;
}
```


