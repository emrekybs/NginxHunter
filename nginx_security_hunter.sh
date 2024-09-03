#!/bin/bash

echo -e "\e[32m"
echo "  _   _   _   _   _     _   _   _   _   _   _  "
echo " / \ / \ / \ / \ / \   / \ / \ / \ / \ / \ / \ "
echo "( N | g | i | n | x ) ( H | u | n | t | e | r )"
echo " \_/ \_/ \_/ \_/ \_/   \_/ \_/ \_/ \_/ \_/ \_/ "
echo -e "\e[31m"
echo "GitHub: https://github.com/emrekybs"
echo "Author: Emre Koybasi (bloodbane)"
echo -e "\e[0m"


### Statistics of Top 20 addresses
### SQL injection analysis
### SQL injection FROM query statistics
### Scanner/common hacker tools
### Vulnerability exploitation detection
### Sensitive path access
### File inclusion attacks
### HTTP Tunnel
### Webshell
### Finding URLs with the top 20 response lengths
### Finding access to rare script files
### Finding 302 redirects for script files

outfile=/tmp/logs

if [ -d $outfile ]; then
    rm -rf $outfile/*
else
    mkdir -p $outfile
fi

access_dir=/var/log/nginx/
access_log=access

num=$(ls ${access_dir}${access_log}* | wc -l) >/dev/null 2>&1
if [ $num -eq 0 ]; then
    echo 'Log file does not exist'
    exit 1
fi
echo -e "\n"

OS='None'
if [ -e "/etc/os-release" ]; then
    source /etc/os-release
    case ${ID} in
    "debian" | "ubuntu" | "devuan")
        OS='Debian'
        ;;
    "centos" | "rhel fedora" | "rhel")
        OS='Centos'
        ;;
    *) ;;
    esac
fi

if [ $OS = 'None' ]; then
    if command -v apt-get >/dev/null 2>&1; then
        OS='Debian'
    elif command -v yum >/dev/null 2>&1; then
        OS='Centos'
    else
         echo -e "\nThis system is not supported\n"
        echo -e "Exiting"
        exit 1
    fi
fi

if ag -V >/dev/null 2>&1; then
     echo -e "\e[00;32msilversearcher-ag is installed \e[00m"
else
    if [ $OS = 'Centos' ]; then
        yum -y install the_silver_searcher >/dev/null 2>&1
    else
        apt-get -y install silversearcher-ag >/dev/null 2>&1
    fi

fi

echo "Analysis result log: ${outfile}"
echo "Nginx log directory: ${access_dir}"
echo "Nginx file name: ${access_log}"
echo -e "\n"

echo -e "\e[00;31m[+]TOP 20 IP adresses\e[00m"
ag -a -o --nofilename '((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}' ${access_dir}${access_log}* | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/top20.log
echo -e "\n"

echo -e "\e[00;31m[+] SQL Injection Attack Analysis \e[00m"

ag -a "xp_cmdshell|%20xor|%20and|%20AND|%20or|%20OR|select%20|%20and%201=1|%20and%201=2|%20from|%27exec|information_schema.tables|load_file|benchmark|substring|table_name|table_schema|%20where%20|%20union%20|%20UNION%20|concat\(|concat_ws\(|%20group%20|0x5f|0x7e|0x7c|0x27|%20limit|\bcurrent_user\b|%20LIMIT|version%28|version\(|database%28|database\(|user%28|user\(|%20extractvalue|%updatexml|rand\(0\)\*2|%20group%20by%20x|%20NULL%2C|sqlmap" ${access_dir}${access_log}* | ag -v '/\w+\.(?:js|css|html|jpg|jpeg|png|htm|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >${outfile}/sql.log
awk '{print "SQL Injection Attack " NR " times"}' ${outfile}/sql.log | tail -n1
echo "SQL Injection TOP 20 IP addresses"
ag -o '(?<=:)((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}' ${outfile}/sql.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/sql_top20.log

echo "SQL Injection FROM Query"
cat ${outfile}/sql.log | ag '\bfrom\b' | ag -v 'information_schema' >${outfile}/sql_from_query.log
awk '{print "SQL Injection FROM Query " NR " times"}' ${outfile}/sql_from_query.log | tail -n1
echo -e "\n"

echo -e "\e[00;31m[+] Scanner Scan & Hacker Tools \e[00m"
ag -a "acunetix|by_wvs|nikto|netsparker|HP404|nsfocus|WebCruiser|owasp|nmap|nessus|HEAD /|AppScan|burpsuite|w3af|ZAP|openVAS|.+avij|.+angolin|360webscan|webscan|XSS@HERE|XSS%40HERE|NOSEC.JSky|wwwscan|wscan|antSword|WebVulnScan|WebInspect|ltx71|masscan|python-requests|Python-urllib|WinHttpRequest" ${access_dir}${access_log}* | ag -v '/\w+\.(?:js|css|jpg|jpeg|png|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >${outfile}/scan.log
awk '{print "A total of " NR " scan attacks detected"}' ${outfile}/scan.log | tail -n1
echo "Top 20 Scanner Tool Traffic"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/scan.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/scan_top20.log
echo -e "\n"

echo -e "\e[00;31m[+] Sensitive Path Access \e[00m"
ag -a "/_cat/|/_config/|include=|phpinfo|info\.php|/web-console|JMXInvokerServlet|/manager/html|axis2-admin|axis2-web|phpMyAdmin|phpmyadmin|/admin-console|/jmx-console|/console/|\.tar.gz|\.tar|\.tar.xz|\.xz|\.zip|\.rar|\.mdb|\.inc|\.sql|/\.config\b|\.bak|/.svn/|/\.git/|\.hg|\.DS_Store|\.htaccess|nginx\.conf|\.bash_history|/CVS/|\.bak|wwwroot|备份|/Web.config|/web.config|/1.txt|/test.txt" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/dir.log
awk '{print "A total of " NR " scans targeting sensitive files detected"}' ${outfile}/dir.log | tail -n1
echo "Top 20 Sensitive File Access Traffic"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/dir.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/dir_top20.log
echo -e "\n"

echo -e "\e[00;31m[+] Vulnerability Exploitation Detection \e[00m"
ag -a "%00|/win.ini|/my.ini|\.\./\.\./|/etc/shadow|%0D%0A|file:/|gopher:/|dict:/|WindowsPowerShell|/wls-wsat/|call_user_func_array|uddiexplorer|@DEFAULT_MEMBER_ACCESS|@java\.lang\.Runtime|OgnlContext|/bin/bash|cmd\.exe|wget\s|curl\s|s=/index/\think" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/exploit.log
awk '{print "Vulnerability exploitation detected " NR " times"}' ${outfile}/exploit.log | tail -n1
echo "Vulnerability Exploitation Detection TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/exploit.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/exploit_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]webshell\e[00m"
ag -a "=whoami|dbname=|exec=|cmd=|\br57\b|\bc99\b|\bc100\b|\bb374k\b|adminer.php|eval\(|assert\(|%eval|%execute|tunnel\.[asp|php|jsp|aspx]{3,4}|makewebtaski|ma\.[asp|php|jsp|aspx]{3,4}|\bup\.[asp|php|jsp|aspx]{3,4}|cmd\.[asp|php|jsp|aspx]{3,4}|201\d\.[asp|php|jsp|aspx]{3,4}|xiaoma\.[asp|php|jsp|aspx]{3,4}|shell\.[asp|php|jsp|aspx]{3,4}|404\.[asp|php|jsp|aspx]{3,4}|tom\.[asp|php|jsp|aspx]{3,4}|k8cmd\.[asp|php|jsp|aspx]{3,4}|ver[0-9]{3,4}\.[asp|php|jsp|aspx]{3,4}|\.aar|[asp|php|jsp|aspx]{3,4}spy\.|o=vLogin|aioshell|admine|ghost\.[asp|php|jsp|aspx]{3,4}|r00ts|90sec|t00ls|editor\.aspx|wso\.[asp|aspx]{3,4}" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' >${outfile}/webshell.log
awk '{print "A total of " NR " webshell activities detected"}' ${outfile}/webshell.log | tail -n1
echo "Webshell TOP 20"
ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' ${outfile}/webshell.log | sort | uniq -c | sort -nr | head -n 20 | tee -a ${outfile}/webshell_top20.log
echo -e "\n"

echo -e "\e[00;31m[+]HTTP Tunnel\e[00m"
ag -a "cmd=disconnect|cmd=read|cmd=forward|cmd=connect|127.0.0.1" ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $0}' | tee -a ${outfile}/tunnel.log
awk '{print "A total of " NR " tunnel activities detected"}' ${outfile}/tunnel.log | tail -n1
echo -e "\n"

echo -e "\e[00;31m[+] Top 20 URLs by Response Length \e[00m"

len=$(cat ${access_dir}${access_log}* | awk '{print $10}' | sort -nr | head -n 20)
echo $len | awk 'BEGIN{ RS=" " }{ print $0 }' | xargs -i{} ag -a --nocolor '\d+\s{}\s' ${access_dir}${access_log}* | awk '{print $7,$10}' | sort | uniq | sort -k 2 -nr | tee -a ${outfile}/url_rsp_len.log
echo -e "\n"

echo -e "\e[00;31m[+] Rare Script File Access \e[00m"
echo "Script files with very low access volume are highly likely to be webshells."
cat ${access_dir}${access_log}* | awk '($9==200)||($9==500) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a ${outfile}/rare_url.log
echo -e "\n"

echo -e "\e[00;31m[+] 302 Redirects \e[00m"
echo "The purpose is to find some script files associated with successful logins."
cat ${access_dir}${access_log}* | awk '($9==302)||($9==301) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a ${outfile}/302_goto.log
echo -e "\n"
