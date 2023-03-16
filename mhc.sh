#!/bin/sh
###################################################################################
##  Script desenvolvido para auxílio na realização de MHC (Manual Health Check)  ##
###################################################################################


# Funções-----------------------------------------------
    function continuar {
        echo 
        echo "*Pressione \033[01;32mEnter\033[01;37m para continuar"
        read y
        clear
    }
 
    function intro {
        clear
        echo "======================================"
        echo
        echo "##        ##   #       #   ########"
        echo "# #      # #   #       #   #"
        echo "#  #    #  #   #########   #"
        echo "#   #  #   #   #       #   #"
        echo "#    ##    #   #       #   ########"
        echo
        echo "======================================"

        continuar
    }

    function ajuda {
        clear
        echo "################################"
        echo "##       Recomendações        ##"
        echo "################################"
        echo 
        echo "1 - De preferência, utilize o MobaXterm como terminal;"
        echo 
        echo "2 - Atente-se no menu, pois o resultado retornado do script dependerá das opções escolhidas;"
        echo
        echo "3 - Encontrou alguma Tech Spech errada/desatualizada? Contate: Matheus.Figueiredo@kyndryl.com"
        echo
        echo "4 - Certifique-se de estar rodando todos os comandos como \033[01;32mROOT\033[01;37m"
        echo
        echo "--------------------------------"
        echo 
        echo 
        echo "#####################################"
        echo "## Como executar em outro servidor ##"
        echo "#####################################"
        echo 
        echo "1 - Realizar o upload do arquivo no FS do usuário"
        echo 
        echo "2 - Alterar a permissão para 755"
        echo 
        echo "3 - Executar o script"
        echo
        echo "--------------------------------"
        continuar
    }

    function regime {
        echo "Regime:"
        echo "1 - Full Manual"
        echo "2 - Gap Only"
        read regime
    }

    function template {
        echo "Template"
        echo "1 - S.O (Linux, AIX)"
        echo "2 - SSH"
        echo "3 - SUDO"
        read template
    }

    function iz1112 {
        # IZ.1.1.1.2
        ## standard password max age is 90, change if needed.
        maxPassAgeEx=365  # maximum password age for non-privileged id's meeting Option A or D.
        file=/etc/shadow
        # eliminate all id's which meet LR*1.1.1.2's 90 day limit requirements or have one of the indicated characters which mark an id without a usable password.
        list2check="$(egrep ^[^:]+:[^\!*x] $file | awk -F: '{if ( $5 == "" || $5 > 90 ) {print $0} }')"
        list3check="$list2check"
        Pgidu=$(grep 'SYS_GID_MAX' /etc/login.defs | awk '{print $2}')
        [ ! -z "${Pgidu##*[!0-9]*}" ] || Pgidu=999 ; # upper limit of GID which grants privilege to users on standard RH install, to be used if parm is not set in login.defs.
        Ugid=100  # 'users' group gid, expressly not privileged.
        PF=pass   # The following identifies any privileged id that does not meet9 (IZ.1.1.9.1).
        for x in $list2check; do
        uName=$(printf "$x" | cut -d: -f1)
        for y in $(groups $uName | cut -d: -f2); do
        gID=$(getent group $y | cut -d: -f3)
        if  [[ "$gID" == "" || ( $gID -ne $Ugid && $gID -le $Pgidu ) ]] ; then PF=$gID ; fi
        done

        if [ "$PF" != "pass" ] ; then
            printf "$uName is a privileged id member group $PF with usable password and fails to meet *.1.1.2 requirement\n"
            list3check=$(printf "$list3check\n"| grep -v "^$uName:")
        fi
        PF=pass
        done
        # determine if ftpd is installed. Used in option A check
        ftpActive=$(systemctl status vsftpd | grep -q "Active: active" ; echo $?) # 0 active, 1 inactive.
        # determine if the file which is used to deny access for option D is correctly setup:
        eRs=$(egrep "auth\s+required\s+.*pam_listfile.so\s+item=user\s+sense=deny\s+file=/etc/security/[^/]+\s+onerr=succeed" /etc/pam.d/system-auth)
        FileName=$(echo $eRs | awk  '{print $6}' | awk -F'/' '{print $4}' )
        eRp=$(egrep "auth\s+required\s+.*pam_listfile.so\s+item=user\s+sense=deny\s+file=/etc/security/$FileName\s+onerr=succeed" /etc/pam.d/password-auth)
        # if $eRp is null, it means one of the two files is missing the requirement parameter, or they do not agree on the file name. # IZ.1.1.13.1.0
        # Now make sure that line is before the 'auth.*sufficient' lines....
        saPF=$(grep ^auth /etc/pam.d/system-auth | awk '{if ($3 ~ "pam_listfile.so$") {print "pass"; exit} else if ($2 == "sufficient") {print "system-auth:Move before _sufficient_ line";exit}}')
        paPF=$(grep ^auth /etc/pam.d/password-auth | awk '{if ($3 ~ "pam_listfile.so$") {print "pass"; exit} else if ($2 == "sufficient") {print "password-auth:Move before _sufficient_ line";exit}}')
        # Finally, check that the ssh parm is set as needed # IZ.1.1.13.4
        UsePAMPF=$(grep '^[^#]*UsePAM\s*yes' /etc/ssh/sshd_config)
        if [[ -n $eRp && $saPF == 'pass' && $paPF == 'pass' && -n $UsePAMPF ]] ; then pamLFconf='ok' ; else pamLFconf='fail' ; fi # sum up all of the configration requirements for pam_listfile (LF)
        PF=fail  # Determine if any non-privileged ID's meet the exceptions requirements for Option A or D.
        for x in $list3check; do
        uName=$(printf "$x" | cut -d: -f1)
        if [[ ( $ftpActive -ne 0 || $(grep -q "^$uName\s*$" /etc/vsftpd/ftpusers; printf "$?") -eq 0 ) ]] ; then ftpOK=0 ; else ftpOK=1 ; fi # pre-check IZ.1.1.10.2 and IZ.1.1.13.3
        if [[ $(grep  "^$uName:" /etc/passwd | egrep -q ":/bin/false|:/sbin/nologin"; printf "$?" ) -eq 0 &&
            $ftpOK -eq 0  ]] ; then PF="OptionA" ; fi # meets both IZ.1.1.10.1 and IZ.1.1.10.2
        if [[ $pamLFconf == 'ok' && $(grep -q "^$uName\s*$" /etc/security/$FileName 2>/dev/null; printf "$?") -eq 0 && $ftpOK -eq 0  ]] ; then PF="optionD" ; fi # check IZ.1.1.13.1.0 && IZ.1.1.13.2 && IZ.1.1.13.3
        if [ "$PF" == "fail" ] ; then
            printf "$uName is not a privileged user and fails to meet any of option A or D for extended password expiration.\n"
        else
            Life=$(printf "$x" | cut -d: -f5)
            if [[ -z "$Life" || "$Life" -gt $maxPassAgeEx ]] ; then
            if [[ -z "$Life" ]] ; then Life="null (unlimited)" ; fi
            printf "$uName is not a privileged user, passes $PF, but has a password expiration of $Life which exceeds the maximum of $maxPassAgeEx.\n"
            fi
        fi

        PF=fail
        done
    }

    function iz1182 {
        
        cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
        users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
        echo "Duplicate UID ($2): ${users}"
        fi
        done

    }

    function iz11831 {
        cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
        [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
        groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
        echo "Duplicate GID ($2): ${groups}"
        fi
        done
    }

    function iz11832 {
        for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        if [ $? -ne 0 ]; then
        echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
        fi
        done
    }

    function full_manual_ssh {
        #full manual ssh toyota 
        echo "Nome da planilha: Toyota-CSDv2.0-MHC-gcm57-SSH Servers-TSv6.1-Feb2023"
        echo
        echo "##################"
        echo "##   AV.1.1.1   ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# "grep "^\s*PermitEmptyPasswords" /etc/ssh/sshd_config"
        grep "^\s*PermitEmptyPasswords" /etc/ssh/sshd_config
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"
        echo "##   AV.1.1.4   ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# "ssh-keygen -y -P '' -f ${HOME}/.ssh/id_rsa"
        ssh-keygen -y -P '' -f ${HOME}/.ssh/id_rsa
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"
        echo "##   AV.1.1.6   ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# "grep "from=.*ssh-" ~/.ssh/authorized_keys"
        grep "from=.*ssh-" ~/.ssh/authorized_keys
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"
        echo "##  AV.1.2.1.2  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# 'grep "^\s*LogLevel" /etc/ssh/sshd_config'
        grep "^\s*LogLevel" /etc/ssh/sshd_config 
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"
        echo "## AV.1.2.1.2.1 ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# 'grep "^\s*LogLevel" /etc/ssh/sshd_config'
        grep "^\s*LogLevel" /etc/ssh/sshd_config 
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"
        echo "##  AV.1.2.1.3  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# 'grep "^\s*LogLevel" /etc/ssh/sshd_config'
        grep "^\s*LogLevel" /etc/ssh/sshd_config 
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo
        echo "Fim da coleta!"
    }

    function full_manual_so {
        #full manual S.O toyota 
        echo "Nome da planilha: Toyota-CSDv2.0-MHC-gcm56-Linux RHEL 7 & 8 -TSv8.1-Feb2023"
        echo
        echo "##################"
        echo "##  IZ.1.1.1.1  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]# " grep PASS_MAX_DAYS /etc/login.defs"
        grep PASS_MAX_DAYS /etc/login.defs
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo
        echo "##################"
        echo "##  IZ.1.1.1.2  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  "cat ./scriptIZ1112.sh"
        iz1112
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo
        echo "##################"
        echo "##  IZ.1.1.1.3  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  'epoch=$(($(date --date "$1" +%s)/86400))'
        epoch=$(($(date --date "$1" +%s)/86400))
        cat /etc/shadow | awk -F: -v epoch="$epoch" '($3 > epoch ) { print $1 " has a future date password change: " $3 " : today epoch is "epoch }'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo
        echo "##################"
        echo "## IZ.1.1.10.1  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]# "getent passwd $User | cut -d: -f7"
        getent passwd $User | cut -d: -f7
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo
        echo "##################"
        echo "## IZ.1.1.10.2  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  "grep "^$User\s*" /etc/vsftpd/ftpusers"
        grep "^$User\s*" /etc/vsftpd/ftpusers
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo
        echo "##################"
        echo "## IZ.1.1.13.1  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  '$file1=/etc/pam.d/system-auth'
        echo [`whoami`@`hostname -s`]#  '$file2=/etc/pam.d/password-auth'
        echo [`whoami`@`hostname -s`]#  'egrep "auth\s+required\s+.*pam_listfile.so\s+item=user\s+sense=deny\s+file=/etc/security/FILNAME\s+onerr=succeed" $file1'
        egrep "auth\s+required\s+.*pam_listfile.so\s+item=user\s+sense=deny\s+file=/etc/security/FILNAME\s+onerr=succeed" /etc/pam.d/system-auth 
        echo [`whoami`@`hostname -s`]#  'egrep "auth\s+required\s+.*pam_listfile.so\s+item=user\s+sense=deny\s+file=/etc/security/FILNAME\s+onerr=succeed" $file2'
        egrep "auth\s+required\s+.*pam_listfile.so\s+item=user\s+sense=deny\s+file=/etc/security/FILNAME\s+onerr=succeed" ^auth /etc/pam.d/password-auth
        grep ^auth /etc/pam.d/system-auth 
        grep ^auth /etc/pam.d/password-auth
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"
        echo "## IZ.1.1.13.2  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  'grep "^$User\s*$" /etc/security/$FILENAME'
        grep "^$User\s*$" /etc/security/$FILENAME
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "## IZ.1.1.13.3  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  'grep "^$User\s*$" /etc/vsftpd/ftpusers'
        grep "^$User\s*$" /etc/vsftpd/ftpusers
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo
        echo "##################"   
        echo "## IZ.1.1.13.4  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  "grep '^[^#]*UsePAM\s*yes' /etc/ssh/sshd_config"
        grep '^[^#]*UsePAM\s*yes' /etc/ssh/sshd_config
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo
        echo "##################"   
        echo "##  IZ.1.1.2.0  ##"
        echo "##################"
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='"
        egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='"
        egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/security/etc/pam.d/system-auth | grep 'pam_pwquality.so'"
        egrep -v '^\s*#' /etc/security/etc/pam.d/system-auth | grep 'pam_pwquality.so'
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/security/etc/pam.d/password-auth | grep 'pam_pwquality.so'"
        egrep -v '^\s*#' /etc/security/etc/pam.d/password-auth | grep 'pam_pwquality.so'
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/security/pwquality.conf | egrep 'minlen\s+=|dcredit\s+=|ucredit\s+=|lcredit\s+=|ocredit\s+=' | sort "
        egrep -v '^\s*#' /etc/security/pwquality.conf | egrep 'minlen\s+=|dcredit\s+=|ucredit\s+=|lcredit\s+=|ocredit\s+=' | sort 
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/security/pwquality.conf | egrep 'minlen\s+=|dcredit\s+=|ucredit\s+=|lcredit\s+=|ocredit\s+=' | sort "
        egrep -v '^\s*#' /etc/security/pwquality.conf | egrep 'minlen\s+=|dcredit\s+=|ucredit\s+=|lcredit\s+=|ocredit\s+=' | sort 
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "##  IZ.1.1.2.1  ##"
        echo "##################"
        cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "##  IZ.1.1.2.2  ##"
        echo "##################"
        cat /etc/passwd | awk -F: '($2 == "" ) { print $1 " has null in second field of /etc/passwd."}'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"        
        echo   
        echo "##################"   
        echo "##  IZ.1.1.3.1  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "grep PASS_MIN_DAYS /etc/login.defs"
        grep PASS_MIN_DAYS /etc/login.defs
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"        
        echo   
        echo "##################"   
        echo "##  IZ.1.1.3.2  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4 | grep -v ':1$'"
        egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4 | grep -v ':1$'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "##  IZ.1.1.4.1  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/system-auth"
        egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/system-auth
        echo [`whoami`@`hostname -s`]#  "egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/password-auth"
        egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/password-auth
        echo [`whoami`@`hostname -s`]#  "egrep '^password\s+.*pam_unix.so' /etc/pam.d/system-auth"
        egrep '^password\s+.*pam_unix.so' /etc/pam.d/system-auth
        echo [`whoami`@`hostname -s`]#  "egrep '^password\s+.*pam_unix.so' /etc/pam.d/password-auth    "
        egrep '^password\s+.*pam_unix.so' /etc/pam.d/password-auth
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "##  IZ.1.1.4.5  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'auth.*pam_unix.so.*nullok'"
        egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'auth.*pam_unix.so.*nullok'
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'auth.*pam_unix.so.*nullok'"
        egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'auth.*pam_unix.so.*nullok'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "##  IZ.1.1.4.6  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  'grep "^password.*deny.so" /etc/pam.d/system-auth'
        grep "^password.*deny.so" /etc/pam.d/system-auth
        echo [`whoami`@`hostname -s`]#  'grep "^password.*deny.so" /etc/pam.d/password-auth'
        grep "^password.*deny.so" /etc/pam.d/password-auth
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "##  IZ.1.1.4.7  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  '"^password\s" /etc/pam.d/system-auth'
        egrep "^password\s" /etc/pam.d/system-auth | awk '{print $3}'
        echo [`whoami`@`hostname -s`]#  'egrep "^password\s" /etc/pam.d/password-auth'
        egrep "^password\s" /etc/pam.d/password-auth | awk '{print $3}'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo   
        echo "##################"   
        echo "##  IZ.1.1.6.0  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "cat /etc/pam.d/system-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'"
        cat /etc/pam.d/system-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'
        echo [`whoami`@`hostname -s`]#  "cat /etc/pam.d/password-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'"
        cat /etc/pam.d/password-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'
        echo [`whoami`@`hostname -s`]#  "cat /etc/pam.d/system-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'"
        cat /etc/pam.d/system-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'
        echo [`whoami`@`hostname -s`]#  "cat /etc/pam.d/password-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'"
        cat /etc/pam.d/password-auth | grep -E 'faillock.so|pam_unix.so' | grep -E '^auth|^account'
        echo [`whoami`@`hostname -s`]#  "grep ^auth /etc/pam.d/system-auth | egrep 'pam_tally2.so.*deny=5'"
        grep ^auth /etc/pam.d/system-auth | egrep 'pam_tally2.so.*deny=5'
        echo [`whoami`@`hostname -s`]#  "grep ^auth /etc/pam.d/password-auth | egrep 'pam_tally2.so.*deny=5'"
        grep ^auth /etc/pam.d/password-auth | egrep 'pam_tally2.so.*deny=5'
        grep ^auth /etc/pam.d/system-auth | awk '{if ($3 == "pam_tally2.so") {print "pass"; exit} else if ($2 == "sufficient") {print "Move before _sufficient_ line";exit}}'
        grep ^auth /etc/pam.d/password-auth | awk '{if ($3 == "pam_tally2.so") {print "pass"; exit} else if ($2 == "sufficient") {print "Move before _sufficient_ line";exit}}'
        grep ^account /etc/pam.d/system-auth | awk '{if ($3 == "pam_tally2.so") {print "pass"; exit} else if ($2 == "sufficient") {print "Move before _sufficient_ line";exit}}'
        grep ^account /etc/pam.d/password-auth | awk '{if ($3 == "pam_tally2.so") {print "pass"; exit} else if ($2 == "sufficient") {print "Move before _sufficient_ line";exit}}'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.7.1  ##"
        echo "##################"
        echo
        grep '^root:' /etc/shadow | awk -F':' '{if ($2 == "*" || substr($2,1,1) == "!") {print "pass"$2} else if ( $5 <= 90 && $5 > 0 ) {print "verify registered."} else {print "root has pw and does not expire in 90 days, fail"} }'
        echo [`whoami`@`hostname -s`]#  
        echo
        echo "------------------"       
        echo 
        echo "##################"   
        echo "##  IZ.1.1.7.2  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "grep pts /etc/securetty"
        grep pts /etc/securetty
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.7.3  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "grep pts /etc/securetty"
        cat /etc/shadow | awk -F':' '{print $1,$2}'
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.8.2  ##"
        echo "##################"
        echo
        iz1182
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "## IZ.1.1.8.3.1 ##"
        echo "##################"
        echo
        iz11831
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.9.0  ##"
        echo "##################"
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.2.0  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='"
        egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='
        echo [`whoami`@`hostname -s`]#  "egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='"
        egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'pam_pwquality.so|pam_cracklib.so.*reject_username' | grep 'minlen=' | grep 'dcredit='|grep 'ucredit=' |grep 'lcredit='| grep 'ocredit='
        echo [`whoami`@`hostname -s`]# 
        echo 
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.2.1  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# 
        cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'
        echo [`whoami`@`hostname -s`]# 
        echo 
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.2.2  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  cat /etc/passwd | awk -F: '($2 == "" ) { print $1 " has null in second field of /etc/passwd."}'
        cat /etc/passwd | awk -F: '($2 == "" ) { print $1 " has null in second field of /etc/passwd."}'
        echo [`whoami`@`hostname -s`]# 
        echo 
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.3.1  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  'grep PASS_MIN_DAYS /etc/login.defs'
        grep PASS_MIN_DAYS /etc/login.defs
        echo [`whoami`@`hostname -s`]# 
        echo 
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.3.2  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4 | grep -v ':1$'"
        egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4 | grep -v ':1$'
        echo [`whoami`@`hostname -s`]# 
        echo 
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.4.1  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# "egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/system-auth"
        egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/system-auth
        echo [`whoami`@`hostname -s`]# " egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/password-auth"
        egrep '^password\s+required\s+pam_pwhistory.so' /etc/pam.d/password-auth
        echo [`whoami`@`hostname -s`]# " egrep '^password\s+.*pam_unix.so' /etc/pam.d/system-auth"
        egrep '^password\s+.*pam_unix.so' /etc/pam.d/system-auth
        echo [`whoami`@`hostname -s`]# " egrep '^password\s+.*pam_unix.so' /etc/pam.d/password-auth"
        egrep '^password\s+.*pam_unix.so' /etc/pam.d/password-auth
        echo [`whoami`@`hostname -s`]# 
        echo 
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.1.4.5  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# " egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'auth.*pam_unix.so.*nullok'"
        egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'auth.*pam_unix.so.*nullok'
        echo [`whoami`@`hostname -s`]# " egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'auth.*pam_unix.so.*nullok'"
        egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'auth.*pam_unix.so.*nullok'
        echo 
       echo "------------------"
        echo  
        echo "##################"   
        echo "##  IZ.1.1.4.6  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]# ' grep "^password.*deny.so" /etc/pam.d/system-auth'
        grep "^password.*deny.so" /etc/pam.d/system-auth
        echo [`whoami`@`hostname -s`]# ' grep "^password.*deny.so" /etc/pam.d/password-auth'
        grep "^password.*deny.so" /etc/pam.d/password-auth
        echo
        echo "------------------"
        echo
        iz1112
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "## IZ.1.2.1.4.1 ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "systemctl is-enabled rsyslog"
        systemctl is-enabled rsyslog
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "## IZ.1.2.1.4.2 ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "grep '^[^#]*$ActionFileDefaultTemplate\s*RSYSLOG_TraditionalFileFormat' /etc/rsyslog.conf"
        grep '^[^#]*$ActionFileDefaultTemplate\s*RSYSLOG_TraditionalFileFormat' /etc/rsyslog.conf
        echo [`whoami`@`hostname -s`]#  "grep '^[^#]*\*.info;mail.none;authpriv.none;cron.none\s*[-]*/var/log/messages' /etc/rsyslog.conf"
        grep '^[^#]*\*.info;mail.none;authpriv.none;cron.none\s*[-]*/var/log/messages' /etc/rsyslog.conf
        echo [`whoami`@`hostname -s`]#  "egrep '^[^#]*authpriv\.\*\s*[-]*/var/log/secure' /etc/rsyslog.conf"
        egrep '^[^#]*authpriv\.\*\s*[-]*/var/log/secure' /etc/rsyslog.conf
        echo [`whoami`@`hostname -s`]#  "grep '^[^#]*\*.info;mail.none;authpriv.none;cron.none\s*[-]*/var/log/messages' /etc/rsyslog.conf"
        grep '^[^#]*\*.info;mail.none;authpriv.none;cron.none\s*[-]*/var/log/messages' /etc/rsyslog.conf
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "## IZ.1.2.1.4.3 ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "grep '^[^#]*\$umask' /etc/rsyslog.conf /etc/rsyslog.d/*.conf | LC_ALL=C sort -V"
        grep '^[^#]*\$umask' /etc/rsyslog.conf /etc/rsyslog.d/*.conf | LC_ALL=C sort -V
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##   IZ.1.2.2   ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "ls /var/log/wtmp"
        ls /var/log/wtmp
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.2.3.1  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "ls /var/log/messages"
        ls /var/log/messages
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.2.4.2  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "grep -v '^\s*#' /etc/pam.d/system-auth | grep pam_tally2.so"
        grep -v '^\s*#' /etc/pam.d/system-auth | grep pam_tally2.so
        echo [`whoami`@`hostname -s`]#  "grep -v '^\s*#' /etc/pam.d/password-auth | grep pam_tally2.so"
        grep -v '^\s*#' /etc/pam.d/password-auth | grep pam_tally2.so
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"        
        echo 
        echo "##################"   
        echo "##  IZ.1.2.4.3  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "grep -v '^\s*#' /etc/pam.d/system-auth | grep pam_faillock.so"
        grep -v '^\s*#' /etc/pam.d/system-auth | grep pam_faillock.so
        echo [`whoami`@`hostname -s`]#  "grep -v '^\s*#' /etc/pam.d/password-auth | grep pam_faillock.so"
        grep -v '^\s*#' /etc/pam.d/password-auth | grep pam_faillock.so
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##   IZ.1.2.5   ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "ls /var/log/secure"
        ls /var/log/secure
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.2.7.1  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  "systemctl status chronyd | grep active"
        systemctl status chronyd | grep active
        echo [`whoami`@`hostname -s`]#  "systemctl status ntpd | grep active"
        systemctl status ntpd | grep active
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.2.7.2  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  'egrep "^(server|pool)" /etc/chrony.conf'
         egrep "^(server|pool)" /etc/chrony.conf
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"        
        echo 
        echo "##################"   
        echo "##  IZ.1.2.7.3  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  'grep ^OPTIONS /etc/sysconfig/chronyd'
        grep ^OPTIONS /etc/sysconfig/chronyd
        echo [`whoami`@`hostname -s`]# 
        echo
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.2.7.4  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  'grep "^restrict.*default" /etc/ntp.conf'
        grep "^restrict.*default" /etc/ntp.conf
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.2.7.5  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  'grep "^(server|pool)" /etc/ntp.conf'
        grep "^(server|pool)" /etc/ntp.conf
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo 
        echo "##################"   
        echo "##  IZ.1.2.7.6  ##"
        echo "##################"
        echo
        echo [`whoami`@`hostname -s`]#  'grep "^ExecStart" /usr/lib/systemd/system/ntpd.service'
        grep "^ExecStart" /usr/lib/systemd/system/ntpd.service
        echo [`whoami`@`hostname -s`]# 
        echo
        echo "------------------"
        echo
        echo "Fim da coleta!"
    }

    function full_manual_sudo {
        echo "oi"
    }

# Fim das Funções-----------------------------------------------


#Início do script ----------------------------------------------
intro
echo "Certifique-se de estar logado como \033[01;32mROOT\033[01;37m, caso contrário o script apresentará \033[05;31mERRO\033[00;37m."
echo
echo "Seu usuário no momento ---> "`whoami`
continuar
clear

x=1
while true $x != "1"
do
echo "Selecione uma opção: "
echo "1 - Continuar"
echo "2 - Ajuda"
echo "0 - Sair"
read aux_opc_1
echo $aux_opc_1
#
    if [ $aux_opc_1 = 1 ]; then
        clear
        ##### aaaaaaaaaaaaa
        regime #escolher Full Manual ou Gap Only
        clear
        template #escolher template (S.O, SSH ou SUDO)
        clear

        if [ $regime = 1 ] && [ $template = 1 ]; then
            echo "Template selecionado: Full Manual - S.O"
            full_manual_so
            elif [ $regime = 1 ] && [ $template = 2 ]; then
            echo "Template selecionado: Full Manual - SSH"
            full_manual_ssh
            elif [ $regime = 1 ] && [ $template = 3 ]; then
            echo "Template selecionado: Full Manual - SUDO"
            full_manul_sudo
        fi

        elif [ $aux_opc_1 = 2 ]; then
            ajuda
        else #Condição caso o número do menu inicial for != de 1 ou 2
            clear
            echo "Encerrando o Script"
            exit 
    fi

done