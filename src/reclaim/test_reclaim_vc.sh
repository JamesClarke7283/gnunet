#!/bin/bash
ego1="ego1_$(tr -dc a-z </dev/urandom | head -c 8 ; echo '')"
ego2="ego2_$(tr -dc a-z </dev/urandom | head -c 8 ; echo '')"
test_vc='{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential"],"issuer":"did:reclaim:1234","issuanceDate":"2018-02-24T05:28:04Z","expirationDate":"2025-02-24T00:00:00Z","credentialSubject":{"id":"did:example:abcdef1234567","name":"Tristan"},"proof":{"type":"RsaSignature2018","created":"2017-06-18T21:19:10Z","proofPurpose":"assertionMethod","verificationMethod":"did:reclaim:1234#key-1","proof":"abc"}}'

# Create Identities 
gnunet-identity -C $ego1 --eddsa
gnunet-identity -C $ego2 --eddsa

ego1_id=$(gnunet-identity -d | grep $ego1 | sed 's/.*- \(.*\) -.*/\1/')
ego2_id=$(gnunet-identity -d | grep $ego2 | sed 's/.*- \(.*\) -.*/\1/')

# Import Credential
gnunet-reclaim -e $ego1 -N cred1 -u VC -V $test_vc
cred1_id=$(gnunet-reclaim -e $ego1 -A | grep cred1 | sed 's/.*ID: \(.*\)/\1/')

# Create Attribute based on Credential
gnunet-reclaim -e $ego1 --add=cred1 --value=name --credential-id=$cred1_id
att1_id=$(gnunet-reclaim -e $ego1 -D | sed 's/.*ID: \(.*\)/\1/')
 
# Issue a ticket for the attribute
gnunet-reclaim -e $ego1 -i cred1 -r $ego2_id &> /dev/null
ticket=$(gnunet-reclaim -e $ego1 -T | sed 's/.*Ticket: \(.*\) | ID:.*/\1/')

# Consume Ticket 
proof=$(gnunet-reclaim -e $ego2 -C $ticket | grep signature | sed 's/.*": "\(.*\)"/\1/')
gnunet-reclaim -e $ego2 -C $ticket | tail -n +3 | jq

if [ "$proof" != "abc" ]; then
    echo "Failed."
    return=1
else
    echo "Success"
    return=0
fi

# Delete Identities
# gnunet-identity -D $ego1
# gnunet-identity -D $ego2

exit $return
