#!/bin/bash

cd ${IROHA_HOME}/config

IROHA_CONF=${IROHA_CONF:-iroha.conf}
IROHA_BLOCK=$(cat ${IROHA_CONF}
  sed -e 's/^.*: "//' -e 's/".*$//')
IROHA_GENESIS=${IROHA_GENESIS:-genesis.block}
IROHA_NODEKEY1=${IROHA_NODEKEY:-testnode2}
IROHA_NODEKEY2=${IROHA_NODEKEY:-newnode1}
IROHA_NODEKEY3=${IROHA_NODEKEY:-testticket}
IROHA_NODEKEY4=${IROHA_NODEKEY:-testuser1}


echo "$ Can you see me? irohad --config ${IROHA_CONF} --genesis_block ${IROHA_GENESIS} --keypair_name ${IROHA_NODEKEY1} --drop_state"

irohad --config ${IROHA_CONF} \
  --overwrite_ledger \ #これを消せばコンテナを消しても記録が残り続ける
  --genesis_block ${IROHA_GENESIS} \
  --keypair_name ${IROHA_NODEKEY1} && ${IROHA_NODEKEY2} && ${IROHA_NODEKEY3} && ${IROHA_NODEKEY4} \
  --drop_state 
