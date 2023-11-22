import asyncio
from pathlib import Path

from starknet_py.hash.address import compute_address
from starknet_py.hash.casm_class_hash import compute_casm_class_hash
from starknet_py.net.account.account import Account
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.schemas.gateway import CasmClassSchema
from starknet_py.net.signer.stark_curve_signer import KeyPair
from starknet_py.net.udc_deployer.deployer import Deployer

testnet = "testnet"
MAX_FEE = 100000000000


async def deploy(contract_name, raw_calldata, net_type):
    try:
        print(contract_name)
        client = None
        if net_type == "testnet":
            client = GatewayClient(net=testnet)
        if net_type == "localnet":
            client = GatewayClient("http://127.0.0.1:5050")
        deployer_account = Account(
                client=client,
                address="0x6fd7354452299b66076d0a7e88a1635cb08506f738434e95ef5cf4ee5af2e0c",
                key_pair=KeyPair(private_key=0x5a04c74b6efdaabfc41975de2498a89ae5418ef5772ff6404b5be1741d58577,
                                 public_key=0x5ae1a840919c6268f6925c6753e42796c3afe44221126ef999124906990ce15),
                chain=StarknetChainId.TESTNET,
        )

        casm_class = CasmClassSchema().loads(Path(f"../../target/dev/session_keys_{contract_name}.compiled_contract_class.json").read_text())
        casm_class_hash = compute_casm_class_hash(casm_class)
        declare_transaction = await deployer_account.sign_declare_v2_transaction(
                compiled_contract=Path(f"../../target/dev/session_keys_{contract_name}.contract_class.json").read_text(),
                compiled_class_hash=casm_class_hash, max_fee=int(1e14))
        print(f"declare_transaction: {hex(declare_transaction.calculate_hash(chain_id=StarknetChainId.TESTNET))}")
        resp = await deployer_account.client.declare(transaction=declare_transaction)
        await deployer_account.client.wait_for_tx(resp.transaction_hash)
        class_hash = resp.class_hash
        print(f"Declared class hash: {class_hash}, {hex(class_hash)}")
        udc_deployer = Deployer()
        contract_deployment = udc_deployer.create_contract_deployment_raw(class_hash=class_hash,
                                                                          raw_calldata=raw_calldata)
        deploy_invoke_transaction = await deployer_account.sign_invoke_transaction(calls=contract_deployment.call, max_fee=int(1e14))
        print(f"deploy_invoke_transaction: {hex(deploy_invoke_transaction.calculate_hash(chain_id=StarknetChainId.TESTNET))}")
        resp = await deployer_account.client.send_transaction(deploy_invoke_transaction)
        await deployer_account.client.wait_for_tx(resp.transaction_hash)
        address = contract_deployment.address
        print(f"Contract address: {hex(address)}")
        file_path = f"./{contract_name}"
        with open(file_path, 'w') as file:
            file.write(hex(address))
        return int(hex(address), 16)
    except Exception as e:
        print(f"{e}")
        file_path = f"{contract_name}"
        with open(file_path, 'r') as file:
            s = file.read()
            print(s)
            return int(s, 16)


async def deploy_acc(contract_name, private_key, salt):
    try:
        key_pair = KeyPair.from_private_key(private_key)

        node_url = "https://starknet-testnet.public.blastapi.io/"
        client = FullNodeClient(node_url=node_url)
        chain = StarknetChainId.TESTNET

        class_hash = await client.get_class_hash_at("0x06f464f321465fa8e3dd7e7e1469ee4498d32f5a5f72cc30a9acfeff2c0e4ccc")

        address = compute_address(
                salt=salt,
                class_hash=class_hash,  # class_hash of the Account declared on the Starknet
                constructor_calldata=[key_pair.public_key],
                deployer_address=0,
        )
        print(f"address_aa {hex(address)}")

        account_deployment_result = await Account.deploy_account(
                address=address,
                class_hash=class_hash,
                salt=salt,
                key_pair=key_pair,
                client=client,
                chain=chain,
                constructor_calldata=[key_pair.public_key],
                max_fee=int(1e15),
        )
        # Wait for deployment transaction to be accepted
        await account_deployment_result.wait_for_acceptance()

        # From now on, account can be used as usual
        account = account_deployment_result.account

        print(f"acc address: {hex(address)}")
        file_path = f"./{contract_name}"
        with open(file_path, 'w') as file:
            file.write(hex(address))
        return int(hex(address), 16)
    except Exception as e:
        print(f"{e}")
        file_path = f"{contract_name}"
        with open(file_path, 'r') as file:
            s = file.read()
            print(s)
            return int(s, 16)


async def main():
    # contract_name = "account"
    # # 0x166db0a0758b72c6c89bf5ac6942aeaa0ee281eaae34f06bee74ce29ae4cd36
    # raw_calldata = [0x452e2e03cde837c53678db13d88a22833f0175090fb9589d1dc658b3e73c603]
    # net_type = "testnet"
    # res = await deploy(contract_name, raw_calldata, net_type)

    contract_name = "Account"
    # 0x166db0a0758b72c6c89bf5ac6942aeaa0ee281eaae34f06bee74ce29ae4cd36
    raw_calldata = [0x452e2e03cde837c53678db13d88a22833f0175090fb9589d1dc658b3e73c603]
    net_type = "testnet"
    res = await deploy_acc(contract_name, "0x123", 0x123)


async def run():
    task = asyncio.create_task(main())
    await task
    ex1 = task.exception()
    if ex1:
        raise ex1


asyncio.run(run())
