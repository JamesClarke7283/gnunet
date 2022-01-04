#!/bin/bash

gnunet-identity -C testego1
gnunet-identity -C testego2
test_vc='{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"],"issuer":"did:reclaim:1234","issuanceDate":"2018-02-24T05:28:04Z","expirationDate":"2025-02-24T00:00:00Z","credentialSubject":{"id":"did:example:abcdef1234567","name":"JaneDoe"},"proof":{"type":"RsaSignature2018","created":"2017-06-18T21:19:10Z","proofPurpose":"assertionMethod","verificationMethod":"did:reclaim:1234#key-1","proof":"abc"}}'
testego2_id=$(gnunet-identity -d | grep testego2 | sed 's/.*- \(.*\) -.*/\1/')
# echo $testego2_id

gnunet-reclaim -e testego1 -N cred1 -u VC -V $test_vc
cred1_id=$(gnunet-reclaim -e testego1 -A | grep cred1 | sed 's/.*ID: \(.*\)/\1/')

gnunet-reclaim -e testego1 --add cred1 --value name --credential-id=$cred1_id
# att1_id=$(gnunet-reclaim -e testego1 -D | sed 's/.*ID: \(.*\)/\1/')
# echo $att1_id

gnunet-reclaim -e testego1 -D

gnunet-reclaim -e testego1 --issue cred1 -r $testego2_id
gnunet-reclaim -e testego1 -T

gnunet-identity -D testego1
gnunet-identity -D testego2
