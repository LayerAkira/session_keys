use array::ArrayTrait;
use array::SpanTrait;
use starknet::ContractAddress;
use starknet::account::Call;

use session_keys::Session::DappSession;

#[starknet::interface]
trait AccountABI<TState> {
    fn __execute__(self: @TState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn __validate__(self: @TState, calls: Array<Call>) -> felt252;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState, class_hash: felt252, contract_address_salt: felt252, _public_key: felt252
    ) -> felt252;
    fn set_public_key(ref self: TState, new_public_key: felt252);
    fn get_public_key(self: @TState) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;

    // Grants persmissions for dapp to execute txs on behalf of user wrt to constraints, can be executed by user itself only
    // only called by user else validate signature if, // called by session dapp invoker to avoid gas spending by user 
    fn grant_permissions(ref self: TState, session: DappSession, signature:(felt252,felt252)); 
    
    //  Revoke specified permissions of the dapp, can be executed either by the user itself or by the dapp in case it got compromised
    fn revoke_permissions(ref self: TState, session: DappSession);

    //Revoke all access for particual dapp caller, only can be invoked by user itself
    fn revoke_all(ref self: TState, dapp_caller: ContractAddress); 
    
    // Return if particulal policy is currently active and call can be executed by dapp_representetive
    fn is_policy_active(self: @TState, dapp_representetive: ContractAddress, call_address: ContractAddress, selector: felt252) -> bool;

    // Executes call wrt to constraints specified
    fn execute_dapp_call(ref self: TState, contract: ContractAddress, selector: felt252, calldata: Span<felt252>) -> Span<felt252>;

    fn execute_dapp_calls(ref self: TState, calls: Span<(ContractAddress, felt252, Span<felt252>)>) -> Array<Span<felt252>>;
}
