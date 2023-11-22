use array::Array;
use starknet::{ContractAddress, SyscallResult, storage_access::StorageAddress, class_hash::ClassHash};
use poseidon::poseidon_hash_span;

#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
struct Timestamp {
    block_number: u64,
    block_time: u64
}


#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
struct GeneralPolicy {
    contract_address: ContractAddress, // which contract dapp allowed to call
    selector: felt252, // which method allowed to be called by dapp of specified contract
    max_calls_allowed: u32 // how many calls allowed to be performed on behalf of user for this method of contracct
}

// TODO:Maybe allow wildcard selector and contract?
#[derive(Drop, Serde, PartialEq)]
struct DappSession {
    invoker: ContractAddress, // dapp invoker that can execute txs on behalf of the user
    valid_from: Timestamp, // from what timestamp this session is valid 
    valid_to: Timestamp, // to what timestamp this session is valid
    request_expiry:Timestamp, // when this dapp request for issue session will expire
    policies: Span<GeneralPolicy>, // what policies user allow to grant
}

trait PoseidonHash<T> {
    fn get_poseidon_hash(self: @T) -> felt252;
}

impl PoseidonHashImpl<T, impl TSerde: Serde<T>, impl TDestruct: Destruct<T>> of PoseidonHash<T> {
    fn get_poseidon_hash(self: @T) -> felt252 {
        let mut serialized: Array<felt252> = ArrayTrait::new();
        Serde::<T>::serialize(self, ref serialized);
        let hashed_key: felt252 = poseidon_hash_span(serialized.span());
        hashed_key
    }
}

fn check_sign(account: ContractAddress, hash: felt252, sign: (felt252, felt252)) { //TODO maybe just edsca check?
    let selector = 0x028420862938116cb3bbdbedee07451ccc54d4e9412dbef71142ad1980a30941; // is_valid_signature
    let (x, y) = sign;
    let mut calldata = ArrayTrait::new();
    calldata.append(hash);
    calldata.append(2);
    calldata.append(x);
    calldata.append(y);
    let mut res = starknet::call_contract_syscall(account, selector, calldata.span());
}

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
    fn execute_dapp_call(ref self: TContractState, contract: ContractAddress, selector: felt252, calldata: Span<felt252>) -> SyscallResult<Span<felt252>>;
}


#[starknet::component]
mod dapp_session_handler_component {
    use core::option::OptionTrait;
    use core::array::ArrayTrait;
    use starknet::{ call_contract_syscall, ContractAddress, get_caller_address, get_block_info, get_contract_address, SyscallResult, storage_access::StorageAddress, class_hash::ClassHash};
    use core::{traits::TryInto, traits::Into, box::BoxTrait};
    use starknet::account::Call;
    use super::{IDappSessionHandler, Timestamp, DappSession,GeneralPolicy,PoseidonHashImpl};
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PermissionGranted: PermissionGranted,
        PermissionRevoked: PermissionRevoked,
        AllPermissionsRevoked: AllPermissionsRevoked,
    }

    #[derive(Drop, starknet::Event)]
    struct PermissionGranted {
        #[key]
        dapp_invoker: ContractAddress,
        valid_from: Timestamp,
        valid_to: Timestamp,
        policies: Span<GeneralPolicy>,
    }

    #[derive(Drop, starknet::Event)]
    struct PermissionRevoked {
        #[key]
        dapp_invoker: ContractAddress,
        policies: Span<GeneralPolicy>,
    }
    #[derive(Drop, starknet::Event)]
    struct AllPermissionsRevoked {
        #[key]
        dapp_invoker: ContractAddress,
    }

    // used internally in contract
    #[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
    struct CallConstraint {
        valid_from: super::Timestamp,
        valid_to: super::Timestamp,
        user_nonce: u32,
        calls_remains: u32
    }

    #[storage]
    struct Storage {
        dapp_permission_to_constraint: LegacyMap::<(ContractAddress, ContractAddress, felt252), CallConstraint>,
        dapp_nonce: LegacyMap::<ContractAddress, u32>,
    }

    #[embeddable_as(DappSessionHandlerable)]
    impl DappSessionHandlerableImpl<TContractState, +HasComponent<TContractState>> of IDappSessionHandler<ComponentState<TContractState>> {
        fn grant_permissions(ref self: ComponentState<TContractState>, session: DappSession, signature:(felt252,felt252)) {
            let caller:ContractAddress = get_caller_address();
            if get_contract_address() == caller  {
                self._grant_permissions(session);
                return;
            }
            let hash = session.get_poseidon_hash();
            super::check_sign(get_contract_address(), hash, signature); // TODO should we assert here?   
            self._grant_permissions(session);
        }

        fn revoke_permissions(ref self: ComponentState<TContractState>, session: DappSession) {
            let mut idx = 0;
            assert (get_contract_address() == get_caller_address() || session.invoker == get_caller_address(), 'only dapp or self');
                
            loop {
                let item = *session.policies.at(idx);
                let mut constraint = self._get_constraint(session.invoker, item.contract_address, item.selector);
                constraint.calls_remains = 0.try_into().unwrap(); // make it zero so never executable from this point of time
                self._set_constraint(session.invoker, item.contract_address, item.selector, constraint);
                idx += 1;
                if idx == session.policies.len() { break;}
            };
            self.emit(PermissionRevoked { dapp_invoker: session.invoker, policies: session.policies});
        }

        fn is_policy_active(self: @ComponentState<TContractState>, dapp_representetive: ContractAddress, call_address: ContractAddress, selector: felt252) -> bool {
            let constraint = self._get_constraint(dapp_representetive, call_address, selector);
            return self._is_active(constraint, dapp_representetive);
        }

        fn revoke_all(ref self: ComponentState<TContractState>, dapp_caller: ContractAddress) {
            assert(get_contract_address() == get_caller_address(), 'Only self');
            let cur_nonce = self.dapp_nonce.read(dapp_caller);
            self.dapp_nonce.write(dapp_caller, cur_nonce + 1);
            self.emit(AllPermissionsRevoked { dapp_invoker: dapp_caller});
        }

        fn execute_dapp_call(ref self: ComponentState<TContractState>, contract: ContractAddress, selector: felt252, calldata: Span<felt252>) -> SyscallResult<Span<felt252>> {
            let caller = get_caller_address();
            let mut constraint = self._get_constraint(caller, contract, selector);
            assert(self._is_active(constraint, caller), 'Not active session');

            constraint.calls_remains = constraint.calls_remains - 1;
            self._set_constraint(caller, contract, selector, constraint);

            return call_contract_syscall(contract, selector, calldata);
        }
    }


    #[generate_trait]
    impl InternalImpl<TContractState, +HasComponent<TContractState>> of InternalTrait<TContractState> {
        fn _is_active(self: @ComponentState<TContractState>, constraint: CallConstraint, dapp_caller: ContractAddress) -> bool {
            if constraint.user_nonce < self.dapp_nonce.read(dapp_caller) { return false;}
            if constraint.calls_remains == 0 { return false;}

            let cur_stamp = self.get_timestamp();
            if cur_stamp.block_number < constraint.valid_from.block_number || cur_stamp.block_time < constraint.valid_from.block_time {
                return false;
            }
            if cur_stamp.block_number > constraint.valid_to.block_number || cur_stamp.block_time > constraint.valid_to.block_time {
                return false;
            }

            return true;
        }

        fn _grant_permissions(ref self: ComponentState<TContractState>, session: DappSession) {            
            let cur_ts = self.get_timestamp();
            assert(session.request_expiry.block_number <= cur_ts.block_number && session.request_expiry.block_time <= cur_ts.block_number, 'Request expired');

            let mut idx = 0;
            let mut constraint = CallConstraint {
                valid_from: session.valid_from,
                valid_to: session.valid_to,
                user_nonce: self.dapp_nonce.read(session.invoker),
                calls_remains: 0
            };
            
            loop {
                let item = *session.policies.at(idx);
                constraint.calls_remains = item.max_calls_allowed;
                self._set_constraint(session.invoker, item.contract_address, item.selector, constraint);
                idx += 1;
                if idx == session.policies.len() {  break; }
            };
            self.emit(PermissionGranted {
                        dapp_invoker: session.invoker,
                        valid_to: session.valid_to,
                        valid_from: session.valid_from,
                        policies: session.policies
                    }
            );
        }

        
        fn _get_constraint(self: @ComponentState<TContractState>, dapp_representetive: super::ContractAddress, call_address: ContractAddress, selector: felt252) -> CallConstraint {
            let constraint: CallConstraint = self.dapp_permission_to_constraint.read((dapp_representetive, call_address, selector));
            return constraint;
        }
        fn _set_constraint(
            ref self: ComponentState<TContractState>,
            dapp_representetive: ContractAddress,
            call_address: ContractAddress,
            selector: felt252,
            call_constraint: CallConstraint
        ) {
            self.dapp_permission_to_constraint.write((dapp_representetive, call_address, selector), call_constraint);
        }

        fn get_timestamp(self: @ComponentState<TContractState>) -> Timestamp {
            let info = get_block_info().unbox();
            return Timestamp { block_number: info.block_number, block_time: info.block_timestamp };
        }
    }
}
