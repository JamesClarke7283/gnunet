#!/bin/bash

declare -A K_PLUGIN
declare -A R_TCP
declare -A R_UDP
declare -A P_PLUGIN

extract_attributes()
{
    line_key=$1
    line=$2
    
    if [ "$line_key" = "P" ]
    then
	n=$(echo $line|cut -d \| -f 1|awk -F: '{print $2}')
	echo $n
	m=$(echo $line|cut -d \| -f 1|awk -F: '{print $3}')
	echo $m
    else
	number=$(echo $line|cut -d \| -f 1| cut -c 2-|cut -d : -f 2 )
	echo $number
    fi
	
    
    nf=$(echo $line|awk -F: '{print NF}')
    for ((i=2;i<=$nf;i++))
    do
	entry=$(echo $line |awk -v i=$i -F\| '{print $i}')
	key=$(echo $entry|cut -d { -f 2|cut -d } -f 1|cut -d : -f 1)
	value=$(echo $entry|cut -d { -f 2|cut -d } -f 1|cut -d : -f 2)
	if [ "$key" = "tcp_port" ]
	then
	    echo tcp port: $value
	    R_TCP[$number]=$value
	elif [ "$key" = "udp_port" ]
	then
	    echo udp port: $value
	    R_UDP[$number]=$value
	elif [ "$key" = "plugin" ]
	then
	    echo plugin: $value
	    echo $line_key
	    if [ "$line_key" = "P" ]
	    then
		P_PLUGIN[$n,$m]=$value
		echo $n $m ${P_PLUGIN[$n,$m]}
	    elif [ "$line_key" = "K" ]
	    then
		K_PLUGIN[$number]=$value
	    fi
	fi
    done
}

read_topology(){
    
local filename=$1
while read line; do
# reading each line
    echo $line
    key=$(cut -c -1 <<< $line)
    if [ "$key" = "M" ]
    then
	LOCAL_M=$(cut -d : -f 2 <<< $line)
	echo $LOCAL_M
    elif [ "$key" = "N" ]
    then
	GLOBAL_N=$(cut -d : -f 2 <<< $line)
	echo $GLOBAL_N
    elif [ "$key" = "X" ]
    then
	KNOWN=$(cut -d : -f 2 <<< $line)
	echo $KNOWN
    elif [ "$key" = "T" ]
    then
	PLUGIN=$(cut -d : -f 2 <<< $line)
	echo $PLUGIN
    elif [ "$key" = "K" ]
    then
	echo know node
	extract_attributes $key $line
    elif [ "$key" = "R" ]
    then
	echo router
	extract_attributes $key $line
    elif [ "$key" = "P" ]
    then
	echo node
	extract_attributes $key $line
    fi
done < $filename
}



