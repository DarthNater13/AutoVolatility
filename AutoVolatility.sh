#!/bin/bash

### SECTION 1 - SETUP SCRIPT
echo "Preparing AutoVolatility Script"

# Get image file
echo "Please type in the image name"
read image

# Convert mem file to string
srch_strings $image > image.str

### SECTION 2 - GATHER INFORMATION
echo "Gathering Information. Please wait..."
## Question 01: What was the IP address of the C2 (Control-and-Command) server? 

connectionsOutput=$(./volatility -f "$image" --profile=WinXPSP2x86 connections)

echo "Possible C2 Server IP Addresses" > results.txt
echo "$connectionsOutput" >> results.txt
echo "$connectionsOutput"

echo "USER ACTION REQUIRED"
echo "Enter the IP Address to analyze further"
read ip
echo "Enter the process id to scan for mutex"
read pid

yarascanOutput=$(./volatility -f "$image" --profile=WinXPSP2x86 yarascan -p $pid -Y "$ip") >> results.txt

## Question 02: What process name and process ID was the backdoor running in? 
## AND
## Question 03: What was the mutex the backdoor was using?
## AND
## Question 04: What type of backdoor was installed?

echo "Mutex Information"
# List of predefined mutants and backdoor names
knownMutexs=(')!VoqA.I4')
knownBackdoors=("Poison Ivy")

MutantOutput=$(./volatility -f "$image" --profile=WinXPSP2x86 handles -p "$pid" -t Mutant)


# Search for Mutexs
index=0
for mutant in "${knownMutexs[@]}"; do
    grep_output=$(echo "$MutantOutput" | grep -F "$mutant")

    if [[ -n "$grep_output" ]]; then
        echo "Mutex '$mutant' found for PID $pid:" >> results.txt
        echo "$grep_output" >> results.txt
        mutantPid=$pid
        backdoor="${knownBackdoors[$index]}"
        break
    fi
    index+=1
done


## Question 05: Where was the backdoor placed on the file system?
## EXTERNAL PLUGINS REQUIRED
if [[ "$backdoor" == "Poison Ivy" ]]; then
    poisonIvyPluginOutput=$(./volatility --plugins=plugins.zip -f $image --profile=WinXPSP2x86 poisonivyconfig -p $pid)
    echo "Backdoor Original File" >> results.txt
    originalFile=$(echo "$poisonIvyPluginOutput" | grep 'Original file')
    echo "$originalFile" >> results.txt
fi

## Question 06: What commands were ran on the system?
echo "Commands Ran" >> results.txt
cmdOutput=$(grep "cmd.exe \-" image.str)
echo "$cmdOutput" >> results.txt
echo "No output indicates that no commands were detected within the image" >> results.txt

## Question 07: Were documents transferred via FTP?

echo "FTP Information" >> results.txt
ftpOutput=$(grep "ftp \b([0-9]{1,3}\.){3}[0-9]{1,3}\b" image.str)
altFtpOutput=$(grep "open \b([0-9]{1,3}\.){3}[0-9]{1,3}\b" image.str)


echo "$ftpOutput" >> results.txt
echo "$altFtpOutput" >> results.txt
echo "No output indicates that no FTP connections were detected within the image" >> results.txt

## Question 08: What level of privileges did the attacker finally obtain? 
echo "Permissions Obtained" >> results.txt
permissionsOutput=$(./volatility -f $image --profile=WinXPSP2x86 privs -p $pid)
echo "$permissionsOutput" >> results.txt

## Question 09: From which organization/company do you think the attack was originated? Explain. 
echo "IP Lookup Result" >> results.txt
ipLookup=$(./volatility -f $image --profile=WinXPSP2x86)
ipLookupResult=$(whois -I $ip)
echo "$ipLookupResult" >> results.txt

echo "END OF ANALYSIS" >> results.txt