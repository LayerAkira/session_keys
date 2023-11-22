use serde::Serde;
use starknet::ContractAddress;
use starknet::contract_address_to_felt252;
use array::ArrayTrait;
use debug::PrintTrait;


#[cfg(test)]
mod tests {
    use core::traits::Into;
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use core::traits::TryInto;
    use core::result::ResultTrait;
    use snforge_std::declare;
    use starknet::ContractAddress;
    use snforge_std::ContractClassTrait;
    use starknet::info::get_block_number;
    use debug::PrintTrait;
    use starknet::get_caller_address;
    use snforge_std::start_prank;
    use snforge_std::start_warp;
    use snforge_std::stop_warp;
    use snforge_std::stop_prank;
    use core::dict::{Felt252Dict, Felt252DictTrait, SquashedFelt252Dict};

    use session_keys::utils::erc20::IERC20Dispatcher;
    use session_keys::utils::erc20::IERC20DispatcherTrait;
    use session_keys::utils::account::AccountABIDispatcher;
    use session_keys::utils::account::AccountABIDispatcherTrait;
    use session_keys::Session::DappSession;
    use session_keys::Session::Timestamp;
    use session_keys::Session::PoseidonHashImpl;
    use session_keys::Session::GeneralPolicy;
    use snforge_std::signature::{ StarkCurveKeyPair, StarkCurveKeyPairTrait, Signer, Verifier };
    use snforge_std::cheatcodes::contract_class::ContractClass;

    fn print_u(res: u256) {
        let a: felt252 = res.try_into().unwrap();
        let mut output: Array<felt252> = ArrayTrait::new();
        output.append(a);
        debug::print(output);
    }

    fn get_funds(reciever: ContractAddress, amount: u256) {
        let caller_who_have_funds: ContractAddress =
            0x00121108c052bbd5b273223043ad58a7e51c55ef454f3e02b0a0b4c559a925d4
            .try_into()
            .unwrap();
        let ETH_address: ContractAddress =
            0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
            .try_into()
            .unwrap();
        let ETH = IERC20Dispatcher { contract_address: ETH_address };
        start_prank(ETH.contract_address, caller_who_have_funds);
        ETH.transfer(reciever, amount);
        stop_prank(ETH.contract_address);
    }

    fn get_balance(address: ContractAddress) -> u256 {
        let ETH_address: ContractAddress =
            0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
            .try_into()
            .unwrap();
        let ETH = IERC20Dispatcher { contract_address: ETH_address };
        ETH.balanceOf(address)
    }

    fn get_acc(cls: ContractClass, pub_key: felt252) -> ContractAddress {
        let mut constructor: Array::<felt252> = ArrayTrait::new();
        constructor.append(pub_key);
        let deployed = cls.deploy(@constructor).unwrap();
        return deployed;
    }

    fn print_felt(res: felt252){
        let a: felt252 = res.try_into().unwrap();
        let mut output: Array<felt252> = ArrayTrait::new();
        output.append(a);
        debug::print(output);
    }

    #[test]
    // #[ignore]
    //#[available_gas(10000000000)]
    #[fork("latest")]
    fn test_success_call() {
        let amount = 1000000000000000000;
        assert(1 == 1, 'LOL');

        let ETH_address: ContractAddress =
            0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
            .try_into()
            .unwrap();
        let ETH = IERC20Dispatcher { contract_address: ETH_address };



        let mut key_pair = StarkCurveKeyPairTrait::generate();
        let mut key_pair_01 = StarkCurveKeyPairTrait::generate();
        let cls = declare('Account');
        let acc_address: ContractAddress = get_acc(cls, key_pair.public_key);
        let dapp_address: ContractAddress = get_acc(cls, key_pair_01.public_key);
        let reciever_address: ContractAddress = 0x052d8e9778d026588a51595e30b0f45609b4f771eecf0e335cdefed1d84a9d89.try_into().unwrap();

        get_funds(acc_address, amount);
        get_funds(dapp_address, amount);

        let aa = AccountABIDispatcher { contract_address: acc_address };
        let dapp = AccountABIDispatcher { contract_address: dapp_address };

        let transfer_selector:felt252 = 0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;

        let general_policy = GeneralPolicy{
                contract_address: ETH.contract_address, // which contract dapp allowed to call
                selector: transfer_selector, // which method allowed to be called by dapp of specified contract
                max_calls_allowed: 1 // how many calls allowed to be performed on behalf of user for this method of contracct
        };

        let mut general_policies = ArrayTrait::new();
        general_policies.append(general_policy);

        let dapp_session = DappSession{
                invoker: dapp_address, // dapp invoker that can execute txs on behalf of the user
                valid_from: Timestamp{block_number:0, block_time:0}, // from what timestamp this session is valid 
                valid_to: Timestamp{block_number:907230, block_time:10000000000000}, // to what timestamp this session is valid
                request_expiry:Timestamp{block_number:907230, block_time:10000000000000}, // when this dapp request for issue session will expire
                policies: general_policies.span(), // what policies user allow to grant
        };


        let message_hash = dapp_session.get_poseidon_hash();
        let signature = key_pair.sign(message_hash).unwrap();
        aa.grant_permissions(dapp_session, signature);



        let prev_b = get_balance(reciever_address);
        start_prank(aa.contract_address, dapp.contract_address);
        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(reciever_address.into());
        calldata.append(0x1);
        calldata.append(0x0);
        
        aa.execute_dapp_call(ETH.contract_address, transfer_selector, calldata.span());
        stop_prank(aa.contract_address);
        assert(get_balance(reciever_address) - prev_b == 1, 'wrong_balance test_01');

    }


    #[test]
    // #[ignore]
    //#[available_gas(10000000000)]
    #[should_panic(expected: ('Not active session',))]
    #[fork("latest")]
    fn test_calls_remains_fail() {
        let amount = 1000000000000000000;
        assert(1 == 1, 'LOL');

        let ETH_address: ContractAddress =
            0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
            .try_into()
            .unwrap();
        let ETH = IERC20Dispatcher { contract_address: ETH_address };



        let mut key_pair = StarkCurveKeyPairTrait::generate();
        let mut key_pair_01 = StarkCurveKeyPairTrait::generate();
        let cls = declare('Account');
        let acc_address: ContractAddress = get_acc(cls, key_pair.public_key);
        let dapp_address: ContractAddress = get_acc(cls, key_pair_01.public_key);
        let reciever_address: ContractAddress = 0x052d8e9778d026588a51595e30b0f45609b4f771eecf0e335cdefed1d84a9d89.try_into().unwrap();

        get_funds(acc_address, amount);
        get_funds(dapp_address, amount);

        let aa = AccountABIDispatcher { contract_address: acc_address };
        let dapp = AccountABIDispatcher { contract_address: dapp_address };

        let transfer_selector:felt252 = 0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;

        let general_policy = GeneralPolicy{
                contract_address: ETH.contract_address, // which contract dapp allowed to call
                selector: transfer_selector, // which method allowed to be called by dapp of specified contract
                max_calls_allowed: 1 // how many calls allowed to be performed on behalf of user for this method of contracct
        };

        let mut general_policies = ArrayTrait::new();
        general_policies.append(general_policy);

        let dapp_session = DappSession{
                invoker: dapp_address, // dapp invoker that can execute txs on behalf of the user
                valid_from: Timestamp{block_number:0, block_time:0}, // from what timestamp this session is valid 
                valid_to: Timestamp{block_number:907230, block_time:10000000000000}, // to what timestamp this session is valid
                request_expiry:Timestamp{block_number:907230, block_time:10000000000000}, // when this dapp request for issue session will expire
                policies: general_policies.span(), // what policies user allow to grant
        };


        let message_hash = dapp_session.get_poseidon_hash();
        let signature = key_pair.sign(message_hash).unwrap();
        aa.grant_permissions(dapp_session, signature);



        let prev_b = get_balance(reciever_address);

        start_prank(aa.contract_address, dapp.contract_address);

        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(reciever_address.into());
        calldata.append(0x1);
        calldata.append(0x0);
        
        aa.execute_dapp_call(ETH.contract_address, transfer_selector, calldata.span());
        stop_prank(aa.contract_address);

        assert(get_balance(reciever_address) - prev_b == 1, 'wrong_balance test_01');

        start_prank(aa.contract_address, dapp.contract_address);

        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(reciever_address.into());
        calldata.append(0x1);
        calldata.append(0x0);
        
        aa.execute_dapp_call(ETH.contract_address, transfer_selector, calldata.span());
        stop_prank(aa.contract_address);

    }


        #[test]
    // #[ignore]
    //#[available_gas(10000000000)]
    #[should_panic(expected: ('Request expired',))]
    #[fork("latest")]
    fn test_time_request_expired() {
        let amount = 1000000000000000000;
        assert(1 == 1, 'LOL');

        let ETH_address: ContractAddress =
            0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
            .try_into()
            .unwrap();
        let ETH = IERC20Dispatcher { contract_address: ETH_address };



        let mut key_pair = StarkCurveKeyPairTrait::generate();
        let mut key_pair_01 = StarkCurveKeyPairTrait::generate();
        let cls = declare('Account');
        let acc_address: ContractAddress = get_acc(cls, key_pair.public_key);
        let dapp_address: ContractAddress = get_acc(cls, key_pair_01.public_key);
        let reciever_address: ContractAddress = 0x052d8e9778d026588a51595e30b0f45609b4f771eecf0e335cdefed1d84a9d89.try_into().unwrap();

        get_funds(acc_address, amount);
        get_funds(dapp_address, amount);

        let aa = AccountABIDispatcher { contract_address: acc_address };
        let dapp = AccountABIDispatcher { contract_address: dapp_address };

        let transfer_selector:felt252 = 0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;

        let general_policy = GeneralPolicy{
                contract_address: ETH.contract_address, // which contract dapp allowed to call
                selector: transfer_selector, // which method allowed to be called by dapp of specified contract
                max_calls_allowed: 1 // how many calls allowed to be performed on behalf of user for this method of contracct
        };

        let mut general_policies = ArrayTrait::new();
        general_policies.append(general_policy);

        let dapp_session = DappSession{
                invoker: dapp_address, // dapp invoker that can execute txs on behalf of the user
                valid_from: Timestamp{block_number:0, block_time:0}, // from what timestamp this session is valid 
                valid_to: Timestamp{block_number:907228, block_time:10000000000000}, // to what timestamp this session is valid
                request_expiry:Timestamp{block_number:907228, block_time:10000000000000}, // when this dapp request for issue session will expire
                policies: general_policies.span(), // what policies user allow to grant
        };


        let message_hash = dapp_session.get_poseidon_hash();
        let signature = key_pair.sign(message_hash).unwrap();
        aa.grant_permissions(dapp_session, signature);



        let prev_b = get_balance(reciever_address);

        start_prank(aa.contract_address, dapp.contract_address);

        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(reciever_address.into());
        calldata.append(0x1);
        calldata.append(0x0);
        
        aa.execute_dapp_call(ETH.contract_address, transfer_selector, calldata.span());
        stop_prank(aa.contract_address);

        assert(get_balance(reciever_address) - prev_b == 1, 'wrong_balance test_01');

    }

            #[test]
    // #[ignore]
    //#[available_gas(10000000000)]
    #[should_panic(expected: ('Not active session',))]
    #[fork("latest")]
    fn test_time_to_expired() {
        let amount = 1000000000000000000;
        assert(1 == 1, 'LOL');

        let ETH_address: ContractAddress =
            0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
            .try_into()
            .unwrap();
        let ETH = IERC20Dispatcher { contract_address: ETH_address };



        let mut key_pair = StarkCurveKeyPairTrait::generate();
        let mut key_pair_01 = StarkCurveKeyPairTrait::generate();
        let cls = declare('Account');
        let acc_address: ContractAddress = get_acc(cls, key_pair.public_key);
        let dapp_address: ContractAddress = get_acc(cls, key_pair_01.public_key);
        let reciever_address: ContractAddress = 0x052d8e9778d026588a51595e30b0f45609b4f771eecf0e335cdefed1d84a9d89.try_into().unwrap();

        get_funds(acc_address, amount);
        get_funds(dapp_address, amount);

        let aa = AccountABIDispatcher { contract_address: acc_address };
        let dapp = AccountABIDispatcher { contract_address: dapp_address };

        let transfer_selector:felt252 = 0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;

        let general_policy = GeneralPolicy{
                contract_address: ETH.contract_address, // which contract dapp allowed to call
                selector: transfer_selector, // which method allowed to be called by dapp of specified contract
                max_calls_allowed: 1 // how many calls allowed to be performed on behalf of user for this method of contracct
        };

        let mut general_policies = ArrayTrait::new();
        general_policies.append(general_policy);

        let dapp_session = DappSession{
                invoker: dapp_address, // dapp invoker that can execute txs on behalf of the user
                valid_from: Timestamp{block_number:0, block_time:0}, // from what timestamp this session is valid 
                valid_to: Timestamp{block_number:907228, block_time:10000000000000}, // to what timestamp this session is valid
                request_expiry:Timestamp{block_number:907230, block_time:10000000000000}, // when this dapp request for issue session will expire
                policies: general_policies.span(), // what policies user allow to grant
        };


        let message_hash = dapp_session.get_poseidon_hash();
        let signature = key_pair.sign(message_hash).unwrap();
        aa.grant_permissions(dapp_session, signature);



        let prev_b = get_balance(reciever_address);

        start_prank(aa.contract_address, dapp.contract_address);

        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(reciever_address.into());
        calldata.append(0x1);
        calldata.append(0x0);
        
        aa.execute_dapp_call(ETH.contract_address, transfer_selector, calldata.span());
        stop_prank(aa.contract_address);

        assert(get_balance(reciever_address) - prev_b == 1, 'wrong_balance test_01');

    }



    #[test]
    // #[ignore]
    //#[available_gas(10000000000)]
    #[should_panic(expected: ('Not active session',))]
    #[fork("latest")]
    fn test_wrong_caller() {
        let amount = 1000000000000000000;
        assert(1 == 1, 'LOL');

        let ETH_address: ContractAddress =
            0x049D36570D4e46f48e99674bd3fcc84644DdD6b96F7C741B1562B82f9e004dC7
            .try_into()
            .unwrap();
        let ETH = IERC20Dispatcher { contract_address: ETH_address };



        let mut key_pair = StarkCurveKeyPairTrait::generate();
        let mut key_pair_01 = StarkCurveKeyPairTrait::generate();
        let cls = declare('Account');
        let acc_address: ContractAddress = get_acc(cls, key_pair.public_key);
        let dapp_address: ContractAddress = get_acc(cls, key_pair_01.public_key);
        let reciever_address: ContractAddress = 0x052d8e9778d026588a51595e30b0f45609b4f771eecf0e335cdefed1d84a9d89.try_into().unwrap();

        get_funds(acc_address, amount);
        get_funds(dapp_address, amount);

        let aa = AccountABIDispatcher { contract_address: acc_address };
        let dapp = AccountABIDispatcher { contract_address: dapp_address };

        let transfer_selector:felt252 = 0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;

        let general_policy = GeneralPolicy{
                contract_address: ETH.contract_address, // which contract dapp allowed to call
                selector: transfer_selector, // which method allowed to be called by dapp of specified contract
                max_calls_allowed: 1 // how many calls allowed to be performed on behalf of user for this method of contracct
        };

        let mut general_policies = ArrayTrait::new();
        general_policies.append(general_policy);

        let dapp_session = DappSession{
                invoker: dapp_address, // dapp invoker that can execute txs on behalf of the user
                valid_from: Timestamp{block_number:0, block_time:0}, // from what timestamp this session is valid 
                valid_to: Timestamp{block_number:907228, block_time:10000000000000}, // to what timestamp this session is valid
                request_expiry:Timestamp{block_number:907230, block_time:10000000000000}, // when this dapp request for issue session will expire
                policies: general_policies.span(), // what policies user allow to grant
        };


        let message_hash = dapp_session.get_poseidon_hash();
        let signature = key_pair.sign(message_hash).unwrap();
        aa.grant_permissions(dapp_session, signature);



        let prev_b = get_balance(reciever_address);

        let wong_caller_address:ContractAddress = 0x0.try_into().unwrap();

        start_prank(aa.contract_address, wong_caller_address);

        let mut calldata: Array<felt252> = ArrayTrait::new();
        calldata.append(reciever_address.into());
        calldata.append(0x1);
        calldata.append(0x0);
        
        aa.execute_dapp_call(ETH.contract_address, transfer_selector, calldata.span());
        stop_prank(aa.contract_address);

        assert(get_balance(reciever_address) - prev_b == 1, 'wrong_balance test_01');

    }
}