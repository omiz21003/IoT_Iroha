#!/bin/bash

cd ${IROHA_HOME}/config

IROHA_CONF=${IROHA_CONF:-iroha.conf}
IROHA_BLOCK=$(cat ${IROHA_CONF}
  sed -e 's/^.*: "//' -e 's/".*$//')
IROHA_GENESIS=${IROHA_GENESIS:-genesis.block}
IROHA_NODEKEY=${IROHA_NODEKEY:-testnode2}


echo "$ Can you see me? irohad --config ${IROHA_CONF} --genesis_block ${IROHA_GENESIS} --keypair_name ${IROHA_NODEKEY} --drop_state"

irohad --config ${IROHA_CONF} \
  --genesis_block ${IROHA_GENESIS} \
  --keypair_name ${IROHA_NODEKEY} \
  --drop_state \
  --overwrite_ledger
