#!/usr/bin/env python3
#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

# Here are Iroha dependencies.
# Python library generally consists of 3 parts:
# Iroha, IrohaCrypto and IrohaGrpc which we need to import:
import os
import sys
import binascii
from grpc import RpcError, StatusCode
import inspect  # inspect.stack(0)
from iroha import Iroha, IrohaGrpc, IrohaCrypto
from functools import wraps
from utilities.errorCodes2Hr import get_proper_functions_for_commands

# The following line is actually about the permissions
# you might be using for the transaction.
# You can find all the permissions here:
# https://iroha.readthedocs.io/en/main/develop/api/permissions.html
from iroha.primitive_pb2 import can_set_my_account_detail

if sys.version_info[0] < 3:
    raise Exception('Python 3 or a more recent version is required.')


# Here is the information about the environment and admin account information:
IROHA_HOST_ADDR = os.getenv('IROHA_HOST_ADDR', '127.0.0.1')
IROHA_PORT = os.getenv('IROHA_PORT', '50051')
ADMIN_ACCOUNT_ID = os.getenv('ADMIN_ACCOUNT_ID', 'admin@test')
ADMIN_PRIVATE_KEY = os.getenv(
    'ADMIN_PRIVATE_KEY', 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70')

# Here we will create user keys
user_private_key = IrohaCrypto.private_key()
user_public_key = IrohaCrypto.derive_public_key(user_private_key)
iroha = Iroha(ADMIN_ACCOUNT_ID)
net = IrohaGrpc(f'{IROHA_HOST_ADDR}:{IROHA_PORT}')


def trace(func):
    """
    A decorator for tracing methods' begin/end execution points
    """
    @wraps(func)
    def tracer(*args, **kwargs):
        name = func.__name__
        stack_size = int(len(inspect.stack(0)) / 2)  # @wraps(func) is also increasing the size
        indent = stack_size*'\t'
        print(f'{indent} > Entering "{name}": args: {args}')
        result = func(*args, **kwargs)
        print(f'{indent} < Leaving "{name}"')
        return result

    return tracer


@trace
def send_transaction_and_print_status(transaction):
    hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
    creator_id = transaction.payload.reduced_payload.creator_account_id
    commands = get_commands_from_tx(transaction)
    print(f'Transaction "{commands}",'
          f' hash = {hex_hash}, Ticket-Creator = {creator_id}')
    net.send_tx(transaction)
    for i, status in enumerate(net.tx_status_stream(transaction)):
        status_name, status_code, error_code = status
        print(f"{i}: status_name={status_name}, status_code={status_code}, "
              f"error_code={error_code}")
        print(f'may be good')
        if status_name in ('STATEFUL_VALIDATION_FAILED', 'STATELESS_VALIDATION_FAILED', 'REJECTED'):
            error_code_hr = get_proper_functions_for_commands(commands)(error_code)
            print(f'error dayo!')
            raise RuntimeError(f"{status_name} failed on tx: "
                               f"{transaction} due to reason {error_code}: "
                               f"{error_code_hr}")


def get_commands_from_tx(transaction):
    commands_from_tx = []
    for command in transaction.payload.reduced_payload.__getattribute__("commands"):
        print(f'get Commands!')
        listed_fields = command.ListFields()
        commands_from_tx.append(listed_fields[0][0].name)
    return commands_from_tx


# For example, below we define a transaction made of 2 commands:
# CreateDomain and CreateAsset.
# Each of Iroha commands has its own set of parameters and there are many commands.
# You can check out all of them here:
# https://iroha.readthedocs.io/en/main/develop/api/commands.html
@trace
def create_ticket(domain: str, tag_id: str, precision=2):
    """
    Creates asset with specific precision provided by arguments
    """
    commands = [
        iroha.command('CreateAsset', asset_name=tag_id,
                      domain_id=domain, precision=precision)
    ]
# And sign the transaction using the keys from earlier:
    tx = IrohaCrypto.sign_transaction(
        iroha.transaction(commands), ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)
    print(f'sent transaction!')
# You can define queries
# (https://iroha.readthedocs.io/en/main/develop/api/queries.html)
# the same way.
@trace
def create_domain(domain: str, default_role='p_admin'):
     commands = [
        iroha.command('CreateDomain', domain_id=domain, default_role=default_role)
     ]
# And sign the transaction using the keys from earlier:
     tx = IrohaCrypto.sign_transaction(
        iroha.transaction(commands), ADMIN_PRIVATE_KEY)
     send_transaction_and_print_status(tx)
     print(f'sent transaction!')

@trace
def add_coin_to_admin(tag_id: str, amount='1000.00'):
    """
    Add provided amount of specific units to admin account
    """
    print(f'we will add! ')
    tx = iroha.transaction([
        iroha.command('AddAssetQuantity',
                      asset_id=tag_id, amount=amount)
    ])
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)


@trace
def create_account(account_id: str, domain: str):
    """
    Create account
    """
    print(f'We will create testSFN')
    tx = iroha.transaction([
        iroha.command('CreateAccount', account_name=account_id, domain_id=domain,
                      public_key=user_public_key)
    ])
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)
    print(f'created account!')


@trace
def transfer_coin(source_account, destination_account, asset_id, amount='999.00'):
    tx = iroha.transaction([
        iroha.command('TransferAsset', src_account_id=source_account,
                      dest_account_id=destination_account, asset_id=asset_id,
                      description='test input transaction!', amount=amount)
    ])
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)
    print(f'transfer !')

@trace
def user_grants_to_admin_set_account_detail_permission(account_id: str):
    """
    Make admin account able to set detail of account
    """
    tx = iroha.transaction([
        iroha.command('GrantPermission', account_id=ADMIN_ACCOUNT_ID,
                      permission=can_set_my_account_detail)
    ], creator_account=account_id)
    IrohaCrypto.sign_transaction(tx, user_private_key)
    send_transaction_and_print_status(tx)


@trace
def set_trust_to_user(account_id: str):
    """
    Set age to user by admin account
    """
    print(f'we will set trust_level')
    tx = iroha.transaction([
        iroha.command('SetAccountDetail',
                      account_id=account_id, key='trust_level', value='10')
    ])
    print(f'set trust_level!')
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)


@trace
def get_coin_info(tag_id: str):
    """
    Get asset info for provided asset
    """
    query = iroha.query('GetAssetInfo', asset_id=tag_id)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)

    response = net.send_query(query)
    data = response.asset_response.asset
    print(f'Asset id = {data.asset_id}, precision = {data.precision}')
    print(f'get_coin_info!')

@trace
def get_account_assets(account_id: str):
    """
    List all the assets of provided user account
    """
    query = iroha.query('GetAccountAssets', account_id=account_id)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)

    response = net.send_query(query)
    data = response.account_assets_response.account_assets
    for asset in data:
        print(f'Asset id = {asset.asset_id}, balance = {asset.balance}')
        return asset.balance

@trace
def get_user_details(account_id: str):
    """
    Get all the kv-storage entries for userone@domain
    """
    query = iroha.query('GetAccountDetail', account_id=account_id)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)

    response = net.send_query(query)
    data = response.account_detail_response
    print(f'Account id = {account_id}, details = {data.detail}')
    print(f'get user_details!')

def iroha_ticket_authorization(account_id: str):
    query = iroha.query('GetAccountAssets', account_id=account_id)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
    response = net.send_query(query)
    data = response.account_assets_response.account_assets
    for asset in data:
          print(f'Asset id = {asset.asset_id}, balance = {asset.balance}')
          print(f'I will check whther it is ok!')

@trace
def iroha_block_query_ticket(account_id: str, tag_id: str, page_size: int):
    query = iroha.query('GetAccountAssetTransactions', account_id=account_id, asset_id=tag_id, page_size= page_size)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
    response = net.send_query(query)
    data = response.transactions_page_response
    print(f'get_block_related_to_tag_id')
    print(data)

if __name__ == '__main__':
    try:
        #print(f'Write the tag_id you want')
        #a_id = input()
        print(f'Write the domain')
        domain = input()
        print(f'Write the username')
        u_id = input()
        #create_domain(domain= domain)
        #create_ticket(domain= domain, tag_id= a_id)
        #add_coin_to_admin(tag_id=a_id+'#'+domain)
        create_account(account_id=u_id, domain=domain)
        #print(f'created account!')
       # transfer_coin('admin@test', u_id+'@'+domain, a_id+'#'+domain)
        user_grants_to_admin_set_account_detail_permission(account_id=u_id+'@'+domain )
        #set_trust_to_user(account_id=u_id+'@'+domain)
        #print(f'trust_level')
        #get_coin_info(tag_id=a_id+'#'+domain)
        #r = redis.Redis(host = '127.0.0.1', port = 6379)
        #hoge=r.get('concealed_tag_id_testufn')
       # print(hoge)
       # print(f'redis_test_get!')
       # hoge_code=hoge.decode()
       # if a_id in hoge_code:
          # print(f'you are criminal')
       # else:
          # print(f'ok_transaction!')
#assert redis_client.smembers('concealed_tag_id_testufn') == b'camera', b'human_sensor', b'location_info_sensor'
#assert redis_client.smembers('concealed_tag_id_testufn').decode('utf-8') =='camera', 'human_sensor', 'location_info_sensor'

        #if get_account_assets(account_id=u_id+'@'+domain)!='1000.00':
          # print(f'success if_procedure!')
           #if():
           #else:
        #else:
        #get_user_details(account_id=u_id+'@'+domain)
    except RpcError as rpc_error:
        if rpc_error.code() == StatusCode.UNAVAILABLE:
            print(f'[E] Iroha is not running in address:'
                  f'{IROHA_HOST_ADDR}:{IROHA_PORT}!')
        else:
            print(e)
    except RuntimeError as e:
        print(e)
