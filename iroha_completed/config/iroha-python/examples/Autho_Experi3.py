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
import socket
import datetime
import sys
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
#Here user info
print(f'Write your domain')
domain = input()
print(f'Write your username')
o_id = input()

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
          f' hash = {hex_hash}, Ticket_creator = {creator_id}')
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
def create_domain(domain: str, default_role='user'):
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
def transfer_coin(source_account, destination_account, asset_id, amount='1000.00'):
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


#@trace
#def get_tag_id_info():
    #ng_tag_ids=['image','thermography','human']
    #ok_tag_ids=['temp','humid','light','fire','smoke','vibration']
    #account_list=['sfn1','sfn2','testsfn1']
    #domain_list=['DS','CR','TC','testDS'] #CR=crime, DS=disaster, TC=testcrime
        #for account_id in account_list:
          #for s_domain in domain_list:
            #query = iroha.query('GetAccountAssets', account_id=account_id+'@'+s_domain)
            #IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
            #response = net.send_query(query)
            #data = response.account_assets_response.account_assets
            #tag_id_list=[]
            #for asset in data:
             #print(f'Asset id = {asset.asset_id}, balance = {asset.balance}')
             #tag_id_list.append=asset.asset_id
            #if  tag_id_list in ng_tag_ids:
                #print(f'you are criminal!!')
            #else:
                #print(f'Please wait a minute until we publish the
def get_account_tagid_assets():
    """
    List all the assets of provided user account
    
    """
    dt = datetime.datetime.now()

    print("-- datetime_type --")
    print(dt)
    print(type(dt))

    ts = datetime.datetime.timestamp(dt)

    print("-- start_authorization --")
    print(ts)
    print(type(ts))

    file1_name = "disclosed_tag_id.txt"  # Create the disclosed tag_id_list
    file2_name = "concealed_tag_id.txt"
    #current directory : iroha/config/iroha-python/example
    # file directory : iroha/config/
    disclosed_tag_ids=[]
    concealed_tag_ids=[]
    file = open(file1_name)
    lines = file.readlines()
    for line in lines:
        line=line.replace("\n", "")
        disclosed_tag_ids.append(line)
    file.close()
    file = open(file2_name)
    lines = file.readlines()
    for line in lines:
        line=line.replace("\n", "")
        concealed_tag_ids.append(line)
    file.close()
    
    
    #ng_tag_ids=['image','thermography','human']
    #ok_tag_ids=['temp','humid','light','fire','smoke','vibration']
    account_list=['sfn1','sfn2'] #If you create more players, you have to write here
    domain_list=['CR','DS'] #CR=crime, DS=disaster, TC=testcrime
        #asset_balance_list=[]
        #asset_id_list=[]
    for u_id in account_list:
       for s_domain in domain_list:
        query = iroha.query('GetAccountAssets', account_id=u_id+'@'+s_domain)
        IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
        response = net.send_query(query)
        data = response.account_assets_response.account_assets
        asset_balance_list=[]
        tag_id_list=[]
        for asset in data:
         print(f'Asset id = {asset.asset_id}, balance = {asset.balance}')
         asset_balance_list.append(float(asset.balance))
         tag_id_list.append(asset.asset_id)
        print(f'We will check whether it is ok?')
        #for tag_id_list in concealed_tag_ids: #search concealed_tag_id
        #for tag_id in tag_id_list:
         # matches = [tag for tag in concealed_tag_ids if tag in tag_id]
         #if any(tag in tag_id for tag in concealed_tag_ids):  # 部分一致チェック
          #if matches:
           # print(f"Match found for tag_id={tag_id}: {matches}")
           #print(f"{asset_balance_list}")
            #if any(balance == 999.00 for balance in asset_balance_list):  # 厳密な比較を行う
             #  print(f"{tag_id}#{s_domain}")
              # print(f'Where is the imposter!!')
              # print(f"{u_id}@{s_domain}")
               #print('You are Criminal!')
            #else:
               #print(tag_id_list+'#'+s_domain)
             #  print(f"{tag_id}#{s_domain}")
             #  print(f'no problem!,or no ticket!')
          #else:
              # print(f'test')
        #print(f'We will subscribe!')
        for tag_id in tag_id_list: #search disclosed_tag_id
           #if '999.00' in asset_balance_list:
           d_tagidsea = datetime.datetime.now()

           print("-- datetime_type --")
           print(d_tagidsea)
           print(type(d_tagidsea))

           t_tagid = datetime.datetime.timestamp(d_tagidsea)

           print("-- Authorized_time_count_start_ALL --")
           print(t_tagid)
           print(type(t_tagid))

           matches = [tag for tag in concealed_tag_ids if tag in tag_id]
           #if any(tag in tag_id for tag in concealed_tag_ids):  # 部分一致チェック
           if matches:
             print(f"Match found for tag_id={tag_id}: {matches}")
             #print(f"{asset_balance_list}")
             if any(balance == 999.00 for balance in asset_balance_list):  # 厳密な比較を行う
                print(f"{tag_id}#{s_domain}")
                print(f'Where is the imposter!!')
                print(f"{u_id}@{s_domain}")
                print('You are Criminal!')
             else:
                #print(tag_id_list+'#'+s_domain)
                print(f"{tag_id}#{s_domain}")
                print(f'no problem!,or no ticket!')

           else:
               for asset in asset_balance_list:
                  print(f"{tag_id}")
                  dt = datetime.datetime.now()

                  print("-- datetime_type --")
                  print(dt)
                  print(type(dt))
                  ts = datetime.datetime.timestamp(dt)

                  if asset != '1000.00':
                   print(f'somebody creates ticket for someone of our group! If we get the amount, we will show you!')
                   if s_domain != domain: #check the domain. if the domain was yours, you'll send your data
                     print(f'The ticket was made for you!') # we will start socket communications to submit(=publish) the data
                     print(f"Destination:{u_id}@{s_domain}")
                     print(f'we will publish!')
                     #transfer_coin('admin@test', u_id+'@'+s_domain, tag_id_list+'#'+s_domain)
                     if o_id == 'ufn1':
                        print(f'publish for sfn2')
                        # publish('133.80.182.41', '50000',tag_id_list+'#'+s_domain.txt) #we counldn't send data between (container and server,container and container)
                     elif o_id == 'ufn2':
                        print(f'publish for sfn1')
                        full_path = f"/opt/IoT_Iroha/iroha/config/iotdata/{tag_id}.txt"
                        publish('133.80.182.42', 50000, full_path)

                        #print(f'publish for ufn2')
                        #publish('133.80.182.42', '50000',tag_id_list+'#'+s_domain.txt)
                   else:
                    print(f'no ticket for the tag!') 
                    print(f"{tag_id_list}#{s_domain}")
                    print(f'no ticket for me orz')
                  e_tag_ids_autho = datetime.datetime.now()

                  print("-- datetime_type --")
                  print(e_tag_ids_autho)
                  print(type(e_tag_ids_autho))

                  a_tagid = datetime.datetime.timestamp(e_tag_ids_autho)
                  print(a_tagid)
                  print(type(a_tagid))
                  print("-- Authorized_time_count_start_every --")
                  everyautho_time=e_tag_ids_autho-dt
                  print(everyautho_time)
             #if s_domain != domain: #check the domain. if the domain was yours, you'll send your data
                #print(f'The ticket was made for you!') # we will start socket communications to submit(=publish) the data
                #if u_id == 'ufn1':
                 #publish() #after publish, execute "transfer-coin"
                #elif u_id == 'ufn2':
                 #publish()
                  print(f'the ticket was not made for you')
           #else:
             #print(tag_id_list+'#'+s_domain)
             #print(f'no ticket for me orz')
    print(f'AUthorization Fin!')
       #if  tag_id_list in ng_tag_ids:
             #print(u_id+'@'+s_domain,tag_id_list+'#'+s_domain)
             #print(f'you are criminal!!')
       #else:
             #print(f'Please wait a minute until we publish the data!') # then we are suppose to submit the data based on the ticket
    #dl = datetime.datetime.now()

    #print("-- datetime_type --")
    #print(dl)
    #print(type(dl))

    #td = datetime.datetime.timestamp(dl)

    #print("-- transaction finished --")
    #print(td)
    #print(type(td))
    #created_time=dl-dt
   # print('Authorization_and_publish_time'+created_time)
def subscribe(ip, port, ext):
    print(f'We will subscribe')
    output_list = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, port))
        s.listen(4)
        while True:
            conn, addr = s.accept()
            with conn:
                dt_now = datetime.datetime.now()
                fname = dt_now.strftime('%Y/%m/%d %H:%M:%S') + "_received." + ext
                with open(fname, mode="ab") as f:
                    while True:
                        data = conn.recv(65535)
                        if not data:
                            print(f'no data')
                            break
                        f.write(data)
                        conn.sendall(b'Received done')
                    exit()
def publish(ip, port, fname):
    print("We will publish!!!orz")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            print(f"Connected to {ip}:{port}")

            try:
                with open(fname, mode='rb') as f:
                    while line := f.read(65535):
                        s.sendall(line)
                        data = s.recv(65535)
                        print(f"Server response: {data.decode('utf-8')}")
            except FileNotFoundError:
                print(f"Error: File '{fname}' not found.")
            except Exception as e:
                print(f"An error occurred while reading or sending the file: {e}")
    except ConnectionRefusedError:
        print("Connection refused. Ensure the server is running and accessible.")
    except Exception as e:
        print(f"An error occurred during the connection: {e}")
@trace
def get_user_details(account_id: str):
    """
    Get all the kv-storage entries for userone@domain
    """
    query = iroha.query('GetAccountDetails', account_id=account_id)
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)

    response = net.send_query(query)
    data = response.account_detail_response
    print(f'Account id = {account_id}, details = {data.detail}')
    print(f'get user_details!')

def iroha_ticket_authorization(account_id: str):
    query = iroha.query('GetAccountAssets', account_id=account_id)
    IrohaCrypto.sign_query(query, ADMIN_account_id=account_id+'@'+s_domain)
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
        #print(f'Write your domain')
        #domain = input()
        #print(f'Write your username')
        #o_id = input()
        #create_domain(domain= domain)
        #create_ticket(domain= domain, tag_id= a_id)
        #add_coin_to_admin(tag_id=a_id+'#'+domain)
        #create_account(account_id=u_id, domain=domain)
        #print(f'created account!')
        #transfer_coin('admin@test', u_id+'@'+domain, a_id+'#'+domain)
        #user_grants_to_admin_set_account_detail_permission(account_id=u_id+'@'+domain )
        #set_trust_to_user(account_id=u_id+'@'+domain)
        #print(f'trust_lev
        #IoT Devices	      Tag IDs
        #Temperature sensor	Temp
        #Humidity sensor  	Humid
        #Light intensity sensor	Light
        #Surveillance camera	Image
        #Fire alarm	        Fire
        #Smoke detector	        Smoke
        #Thermography	        Thermography
        #Vibration detector	Vibration
        #Human sensor           Human
        #ng_tag_ids=['image','thermography','human']
        #ok_tag_ids=['temp','humid','light','fire','smoke','vibration']
        account_list=['sfn1','sfn2']
        domain_list=['DS','CR'] #CR=crime, DS=disaster, TC=testcrime
        #asset_balance_list=[]
        #asset_id_list=[]
        #for u_id in account_list:
         #for s_domain in domain_list:
          #for tag_id in ng_tag_ids: #search ng_tag_id
           #if '999.00' in get_account_assets(account_id=u_id+'@'+s_domain):
              #print(tag_id)
              #print(f'Where is the imposter!!')
           #else:
              #print(f'no problem!')
              #get_account_assets(account_id=u_id+'@'+s_domain)
          #for tag_id in ok_tag_ids: #search ok_tag_id
           #if '999.00' in get_account_assets(account_id=u_id+'@'+s_domain):
              #print(tag_id)
              #print(f'somebody creates ticket for me!')
           #else:
              #print(f'no ticket for me orz')
              #get_account_assets(account_id=u_id+'@'+s_domain)
        #r = redis.Redis(host = '127.0.0.1', port = 6379) #connect to the redis-server
        #hoge=r.get('concealed_tag_id_testufn')
        #print(hoge)
        #print(f'tag_ids_get!')
        get_account_tagid_assets()
        #for account_id in account_list:
          #for s_domain in domain_list:
            #get_account_tag_id_info(account_id=account_id+'@'+s_domain)
            #if get_tag_id_info(account_id=account_id+'@'+s_domain) in ng_tag_ids:
                #print(f'you are criminal!!')
            #else:
                #print(f'Please wait a minute until we publish the data!') # then we are suppose to submit the data based on the ticket
                #get_account_assets(account_id=account_id+'@'+s_domain)
    except RpcError as rpc_error:
        if rpc_error.code() == StatusCode.UNAVAILABLE:
            print(f'[E] Iroha is not running in address:'
                  f'{IROHA_HOST_ADDR}:{IROHA_PORT}!')
        else:
            print(e)
    except RuntimeError as e:
        print(e)
