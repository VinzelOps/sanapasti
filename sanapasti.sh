#!/bin/bash

echo "   ██████  ▄▄▄       ███▄    █  ▄▄▄       ██▓███   ▄▄▄        ██████ ▄▄▄█████▓ ██▓\n"
echo " ▒██    ▒ ▒████▄     ██ ▀█   █ ▒████▄    ▓██░  ██▒▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▓██▒\n"
echo " ░ ▓██▄   ▒██  ▀█▄  ▓██  ▀█ ██▒▒██  ▀█▄  ▓██░ ██▓▒▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██▒\n"
echo "   ▒   ██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██▄█▓▒ ▒░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██░\n"
echo " ▒██████▒▒ ▓█   ▓██▒▒██░   ▓██░ ▓█   ▓██▒▒██▒ ░  ░ ▓█   ▓██▒▒██████▒▒  ▒██▒ ░ ░██░\n"
echo " ▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒   ▓▒█░▒▓▒░ ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░   ░▓  \n"
echo " ░ ░▒  ░ ░  ▒   ▒▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░░▒ ░       ▒   ▒▒ ░░ ░▒  ░ ░    ░     ▒ ░\n"
echo " ░  ░  ░    ░   ▒      ░   ░ ░   ░   ▒   ░░         ░   ▒   ░  ░  ░    ░       ▒ ░\n"
echo "       ░        ░  ░         ░       ░  ░               ░  ░      ░            ░  \n"
echo ""
echo "               Platform Validasi Keamanan dan Pengintaian Otomatis                  "
echo " ${sanapasti}                                                   by @vinzel${reset}\n"                                                                              
              
###############################################################################################################

#Fungsi wordlist
dirsearchWordlist=~/tools/SecLists/Discovery/Web-Content/dirsearch.txt

#Fungsi tools feroxbuster
feroxbuster=~/tools/feroxbuster

#Fungsi penggunaan paramspider
paramspider=~/tools/ParamSpider/paramspider.py

#Fungsi melakukan Httprobing
HTTPXCALL="httpx -silent -no-color -random-agent -ports 80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"

#Fungsi memanggil ip server
server_ip=$(curl -s ifconfig.me)

SECONDS=0
domain=
subreport=

#Utilitasi Penggunaan Awal
usage() { 
  echo ""
  echo "Panduan Memulai Platform Validasi Keamanan dan Pengintaian Otomatis"
  echo ""
  echo -e "Cara Pakai: sudo ./sanapasti.sh -d [TLD] [opsi] 
  
  opsi:
    -a | --alt   : Hanya Permutasi Subdomain	
    -b | --brute : Bruteforce Direktori
    -c | --cors  : Fuzzing pada Cors	
    -f | --fuzz  : CORS/SSRF/XSS/Nuclei/prototype fuzzing	
    -n | --nuclei: Fuzzing menggunakan Nuclei	
    -s | --ssrf  : Fuzzing Kerentanan SSRF	
    -x | --xss   : Fuzzing Kerentanan XSS	  
    -p | --pp    : Fuzzing kerentanan pada Polution" 1>&2; exit 1; 
}

#Fungsi pilihan awal
display_rules() {
  echo ""
  echo "Rules:"
  echo "1. Pastikan Anda menjalankan skrip ini dengan hak akses yang sesuai."
  echo "2. Pilih opsi yang sesuai dari argumen yang disediakan."
  echo "3. Jangan menggabungkan opsi yang tidak kompatibel."
  echo ""
}

#Fungsi memanggil menu
display_menu() {
  echo "Menu:"
  echo "1. Tampilkan Help"
  echo "2. Tampilkan Rules"
  echo "3. Keluar"
  echo -n "Masukkan pilihan Anda (1-3): "
}

#Fungsi memilih menu
menu() {
  while true; do
    display_menu
    read -r choice
    case $choice in
      1)
        usage
        break
        ;;
      2)
        display_rules
        break
        ;;
      3)
        echo "Keluar dari skrip."
        exit 0
        ;;
      *)
        echo "Pilihan tidak valid. Silakan masukkan angka antara 1-3."
        ;;
    esac
    echo ""
  done
}

#Fungsi pengecekan penggunaan
checkhelp(){
  while [ "$1" != "" ]; do
      case $1 in
          -h | --help ) usage exit;;
      esac
      shift
  done
}

#Fungsi penyesuaian opsi
checkargs(){
  while [ "$1" != "" ]; do
      case $1 in
          -a | --alt   )  alt="1";;
          -b | --brute )  brute="1";;
          -f | --fuzz  )  ssrf="1" xss="1" nuclei="1" corse="1" prototype="1" ;;
          -s | --ssrf  )  ssrf="1";;
          -x | --xss   )  xss="1";;
          -n | --nuclei)  nuclei="1";;
          -c | --cors  )  cors="1";;
          -p | --pp    )  prototype="1";;
      esac
      shift
  done
}

if [ $# -eq 0 ]; then
    menu
else
  if [ $# -eq 1 ]; then
    checkhelp "$@"
  fi
fi

if [ $# -gt 1 ]; then
  checkargs "$@"
fi

domain=$2
if [ -z "${domain}" ]; then
   usage; exit 1;
fi 

#Fungsi mengunduh resolver
downloader(){
  wget -q  https://raw.githubusercontent.com/kh4sh3i/Fresh-Resolvers/master/resolvers.txt  -O ./$domain/$foldername/resolvers.txt
  wget -q  https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O ./$domain/$foldername/dns_wordlist.txt
}

#Fungsi memulai listen server (untuk SSRF)
oob_server(){
  echo -e "${green}Memulai Listen Server...${reset}"
  interactsh-client  -v &> ./$domain/$foldername/listen_server.txt & SERVER_PID=$!
  sleep 5 # Fungsi untuk Listen Server
  LISTENSERVER=$(tail -n 1 ./$domain/$foldername/listen_server.txt)
  LISTENSERVER=$(echo $LISTENSERVER | cut -f2 -d ' ')
  echo "Listen server is up $LISTENSERVER with PID=$SERVER_PID"
}

#Fungsi kustomisasi logo
tagline() {
  # Fungsi Memunculkan Logo
  echo -e "${yellow}
#       ___   _   _  __  _   ___   _    ___ _____ __
#    ,' _/ .' \\ / |/ /.' \\ / o |.' \\ ,' _//_  _// /
#   _\\ \`. / o // || // o // _,'/ o /_\\ \`.  / / / /
#  /___, /_n_//_/|_//_n_//_/  /_n_//___,  /_/ /_/  ${reset}"
}

#Fungsi menjalankan pengintaian
mengintai(){
  echo -e "${green}1.Mengintai Subdomain dengan crobat...${reset}"
  crobat -s $domain > ./$domain/$foldername/$domain.txt
  echo "Pengintaian Subdomain dengan Crobat Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent

  echo -e "${green}2.Mengintai Subdomain dengan subfinder...${reset}"
  subfinder -silent  -d $domain -all | sort -u >> ./$domain/$foldername/$domain.txt
  echo "Pengintaian Subdomain dengan Subfinder Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent

  echo -e "${green}3.Mengintai Subdomain dengan assetfinder...${reset}"
  assetfinder -subs-only $domain >> ./$domain/$foldername/$domain.txt
  echo "Pengintaian Subdomain dengan Assetfinder Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}

#Fungsi pengecekan sertifikat SSL
searchcrtsh(){
  echo "${green}Mengecek http://crt.sh ${reset}"
 ~/tools/massdns/scripts/ct.py $domain 2>/dev/null > ./$domain/$foldername/tmp.txt
 [ -s ./$domain/$foldername/tmp.txt ] && cat ./$domain/$foldername/tmp.txt | ~/tools/massdns/bin/massdns -r ./$domain/$foldername/resolvers.txt -t A -q -o S -w  ./$domain/$foldername/crtsh.txt
 echo "Pengecekan Sertifikat SSL Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}

#Fungsi permutasi subdomain
permutatesubdomains(){
  echo "${green}Melakukan permutasi DNS...${reset}"
  cat ./$domain/$foldername/$domain.txt | dnsgen - | sort -u | tee ./$domain/$foldername/dnsgen.txt
  mv ./$domain/$foldername/dnsgen.txt ./$domain/$foldername/$domain.txt
  echo "Pengecekan Permutasi Subdomain Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}

#Fungsi melakukan DNS Probing
dnsprobing(){
  echo "${green}Melakukan pemeriksaan DNS...${reset}"
  cat ./$domain/$foldername/$domain.txt | sort -u |  shuffledns -d $domain -silent -r ./$domain/$foldername/resolvers.txt -o ./$domain/$foldername/shuffledns.txt 
  echo  "${yellow}Total dari $(wc -l ./$domain/$foldername/shuffledns.txt | awk '{print $1}') Subdomain aktif ditemukan${reset}"
  echo "Pengecekan DNS Probing Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}


subdomain_takeover(){
  cat ./$domain/$foldername/shuffledns.txt >> ./$domain/$foldername/temp.txt
  cat ./$domain/$foldername/crtsh.txt >> ./$domain/$foldername/temp.txt


  cat ./$domain/$foldername/temp.txt | awk '{print $3}' | sort -u | while read line; do
  wildcard=$(cat ./$domain/$foldername/temp.txt | grep -m 1 $line)
  echo "$wildcard" >> ./$domain/$foldername/cleantemp.txt
  done

  cat ./$domain/$foldername/cleantemp.txt | grep CNAME >> ./$domain/$foldername/cnames.txt
  cat ./$domain/$foldername/cnames.txt | sort -u | while read line; do
  hostrec=$(echo "$line" | awk '{print $1}')
  if [[ $(host $hostrec | grep NXDOMAIN) != "" ]]
  then
  echo "${red}Mengecek domain yang tidak memiliki NS Record:  $line ${reset}"
  echo "$line" >> ./$domain/$foldername/domain_takeover.txt
  else
  echo -ne "Sedang berjalan...\r"
  fi
  done
  sleep 1
  cat ./$domain/$foldername/$domain.txt > ./$domain/$foldername/alldomains.txt
  cat ./$domain/$foldername/cleantemp.txt | awk  '{print $1}' | while read line; do
  x="$line"
  echo "${x%?}" >> ./$domain/$foldername/alldomains.txt
  done
  sleep 1
  echo "Pengecekan Subdomain Takeover Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}


checkhttprobe(){
  echo "${green} Berburu server web [httpx] Pengujian probe domain...${reset}"
  cat ./$domain/$foldername/$domain.txt | sort -u | $HTTPXCALL -o ./$domain/$foldername/subdomain_live.txt
  echo "Pengecekan Httprobing Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}


#screenshots(){
#  echo "${green}Memulai melakukan screenshot ...${reset}"
#  gowitness file -f ./$domain/$foldername/subdomain_live.txt -P ./$domain/$foldername/screenshots/ --delay 5   -D ./$domain/$foldername/gowitness.sqlite3
#  echo "${green}[screenshot] selesai.${reset}"
#}


getgau(){
  echo "${green}Mengambil url dari wayback,commoncrawl,otx,urlscan...${reset}"
  cat ./$domain/$foldername/subdomain_live.txt | gau -b jpg,jpeg,gif,css,js,tif,tiff,png,ttf,woff,woff2,ico,svg,eot  | qsreplace -a | tee ./$domain/$foldername/gau_output.txt
  echo "${green}gau selesai.${reset}"
  echo "Pengecekan gau Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}

get_interesting(){
  echo "${green}Menemukan data yang tidak biasa...${reset}"
  cat ./$domain/$foldername/gau_output.txt | gf interestingEXT | grep -viE '(\.(js|css|svg|png|jpg|woff))' | qsreplace -a | httpx -mc 200 -silent | awk '{ print $1}' > ./$domain/$foldername/interesting.txt
  echo "Pengecekan Data Anomali Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
}

zip_output(){
zip_name=`date +"%Y_%m_%d-%H.%M.%S"`
zip_name="$zip_name"_"$domain.zip"
(cd $dir && zip -r "$zip_name" .)

echo "Mengirimkan file "${dir}/${zip_name}""
	if [ -s "${dir}/$zip_name" ]; then
		notifikasi "$dir/$zip_name"
		rm -f "${dir}/$zip_name"
	else
		notification "No Zip file to send" warn
	fi
}

notification(){
	if [ -n "$1" ] && [ -n "$2" ]; then
		case $2 in
			info)
				text="\n${bblue} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			warn)
				text="\n${yellow} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			error)
				text="\n${bred} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			good)
				text="\n${bgreen} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
		esac
	fi
}

notifikasi() {
	if [[ -z "$1" ]]; then
		printf "\n${yellow} no file provided to send ${reset}\n"
	else
		if [[ -z "$NOTIFY_CONFIG" ]]; then
			NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
		fi
		if [ -n "$(find "${1}" -prune -size +8000000c)" ]; then
    		printf '%s is larger than 8MB, sending over transfer.sh\n' "${1}"
			transfer "${1}" | notify
			return 0
		fi
		if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Telegram" info
			telegram_chat_id=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_chat_id\|^telegram_chat_id\|^    telegram_chat_id' | xargs | cut -d' ' -f2)
			telegram_key=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_api_key\|^telegram_api_key\|^    telegram_apikey' | xargs | cut -d' ' -f2 )
			curl -F document=@${1} "https://api.telegram.org/bot${telegram_key}/sendDocument?chat_id=${telegram_chat_id}" 2>>"$LOGFILE" &>/dev/null
		fi
		if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Discord" info
			discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url\|^    discord_webhook_url' | xargs | cut -d' ' -f2)
			curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F file1=@${1} $discord_url 2>>"$LOGFILE" &>/dev/null
		fi
		if [[ -n "$slack_channel" ]] && [[ -n "$slack_auth" ]]; then
			notification "Sending ${domain} data over Slack" info
			curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload 2>>"$LOGFILE" &>/dev/null
		fi
	fi
}

directory_bruteforce(){
  echo -e "${green}Memulai melakukan bruteforce penyimpanan dengan FFUF...${reset}"
  for sub in $(cat ./$domain/$foldername/subdomain_live.txt);
    do  
    echo "${yellow} $sub ${reset}"
    ffuf -w $dirsearchWordlist -u $sub/FUZZ  -ac -mc 200 -s -sf  | tee ./$domain/$foldername/reports/$(echo  "$sub" | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g').txt;
    echo "Pengecekan Direktori Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
  done;
}


NucleiScanner(){
  echo -e "${green}Melakukan pengecekan validasi keamanan...${reset}"
  nuclei -silent -iserver "https://$LISTENSERVER" \
    -o ./$domain/$foldername/nuclei.txt \
    -l ./$domain/$foldername/subdomain_live.txt \
    -exclude-templates $HOME/nuclei-templates/misconfiguration/http-missing-security-headers.yaml \
    -exclude-templates $HOME/nuclei-templates/miscellaneous/old-copyright.yaml \
    -t $HOME/nuclei-templates/vulnerabilities/ \
    -t $HOME/nuclei-templates/cnvd/ \
    -t $HOME/nuclei-templates/iot/ \
    -t $HOME/nuclei-templates/cves/2000/ \
    -t $HOME/nuclei-templates/cves/2001/ \
    -t $HOME/nuclei-templates/cves/2002/ \
    -t $HOME/nuclei-templates/cves/2004/ \
    -t $HOME/nuclei-templates/cves/2005/ \
    -t $HOME/nuclei-templates/cves/2006/ \
    -t $HOME/nuclei-templates/cves/2007/ \
    -t $HOME/nuclei-templates/cves/2008/ \
    -t $HOME/nuclei-templates/cves/2009/ \
    -t $HOME/nuclei-templates/cves/2010/ \
    -t $HOME/nuclei-templates/cves/2011/ \
    -t $HOME/nuclei-templates/cves/2012/ \
    -t $HOME/nuclei-templates/cves/2013/ \
    -t $HOME/nuclei-templates/cves/2014/ \
    -t $HOME/nuclei-templates/cves/2015/ \
    -t $HOME/nuclei-templates/cves/2016/ \
    -t $HOME/nuclei-templates/cves/2017/ \
    -t $HOME/nuclei-templates/cves/2018/ \
    -t $HOME/nuclei-templates/cves/2019/ \
    -t $HOME/nuclei-templates/cves/2020/ \
    -t $HOME/nuclei-templates/cves/2021/ \
    -t $HOME/nuclei-templates/cves/2022/ \
    -t $HOME/nuclei-templates/cves/2023/ \
    -t $HOME/nuclei-templates/misconfiguration/ \
    -t $HOME/nuclei-templates/network/ \
    -t $HOME/nuclei-templates/miscellaneous/ \
    -t $HOME/nuclei-templates/takeovers/ \
    -t $HOME/nuclei-templates/default-logins/ \
    -t $HOME/nuclei-templates/exposures/ \
    -t $HOME/nuclei-templates/exposed-panels/ \
    -t $HOME/nuclei-templates/extra_templates/ \
    -t $HOME/nuclei-templates/headless/ \
    -t $HOME/nuclei-templates/helpers/ \
    -t $HOME/nuclei-templates/osint/ \
    -t $HOME/nuclei-templates/ssl/ \
    -t $HOME/nuclei-templates/technologies/ \
    -t $HOME/nuclei-templates/workflows/ \
    -t $HOME/nuclei-templates/fuzzing/

  echo -e "${green}Selesai melakukan validasi keamanan${reset}"
#  notify -bulk -data ./$domain/$foldername/nuclei.txt -silent
}


SSRF_Scanner(){
  echo -e "${green}Mencari kerentanan SSRF ...${reset}"
  cat ./$domain/$foldername/gau_output.txt | gf ssrf | qsreplace https://$LISTENSERVER | httpx -silent 
  notify -bulk -data ./$domain/$foldername/listen_server.txt -silent
}


XSS_Scanner(){
  echo -e "${green}Mencari kerentanan XSS ...${reset}"
  cat ./$domain/$foldername/gau_output.txt | gf xss | qsreplace  -a | httpx -silent -threads 500 -mc 200 |  dalfox pipe -S | tee ./$domain/$foldername/xss_raw_result.txt
  cat ./$domain/$foldername/xss_raw_result.txt | cut -d ' ' -f2 | tee ./$domain/$foldername/xss_result.txt; notify -bulk -data ./$domain/$foldername/xss_result.txt -silent
}


CORS_Scanner(){
  echo -e "${green}Mencari kerentanan CORS ...${reset}"
  cat ./$domain/$foldername/gau_output.txt | qsreplace  -a | httpx -silent -threads 500 -mc 200 | CorsMe - t 70 -output ./$domain/$foldername/cors_result.txt
}


Prototype_Pollution_Scanner(){
  echo -e "${green}Mencari kerentanan Prototype Pollution ...${reset}"
  cat ./$domain/$foldername/gau_output.txt | qsreplace  -a | httpx -silent -threads 500 -mc 200 | ppmap | tee ./$domain/$foldername/prototype_pollution_result.txt
}


kill_listen_server(){
  if [[ -n "$SERVER_PID" ]]; then
    echo "Menonaktifkan Server Sistem $SERVER_PID..."
    kill -9 $SERVER_PID &> /dev/null || true
  fi
}

report()
{
   echo '<html>
    <head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">' >> ./$domain/$foldername/html_report.html
    echo "<title>Laporan Hasil Pengintaian $domain</title>
    <style>.status.redirect{color:#d0b200}.status.fivehundred{color:#DD4A68}.status.jackpot{color:#0dee00}img{padding:5px;width:360px}img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}pre{font-family:Inconsolata,monospace}pre{margin:0 0 20px}pre{overflow-x:auto}article,header,img{display:block}#wrapper:after,.blog-description:after,.clearfix:after{content:}.container{position:relative}html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}h1{margin:.67em 0}h1,h2{margin-bottom:20px}a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}.container,table{width:100%}.site-header{overflow:auto}.post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}p{line-height:1.5em}pre,table td{padding:10px}h2{padding-top:40px;font-weight:900}a{color:#00a0fc}body,html{height:100%}body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}h1{font-size:35px}h2{font-size:28px}p{margin:0 0 30px}pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}.row{display:flex}.column{flex:100%}table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}table th{padding:0 10px 10px;text-align:left}.post-header,.post-title,.site-header{text-align:center}table tr{border-bottom:1px dotted #aeadad}::selection{background:#fff5b8;color:#000;display:block}::-moz-selection{background:#fff5b8;color:#000;display:block}.clearfix:after{display:table;clear:both}.container{max-width:100%}#wrapper{height:auto;min-height:100%;margin-bottom:-265px}#wrapper:after{display:block;height:265px}.site-header{padding:40px 0 0}.site-title{float:left;font-size:14px;font-weight:600;margin:0}.site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}.post-container-left{width:49%;float:left;margin:auto}.post-container-right{width:49%;float:right;margin:auto}.post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}.post-title{font-weight:900;margin:15px 0}.blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}.single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}body.dark{background-color:#1e2227;color:#fff}body.dark pre{background:#282c34}body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}input{font-family:Inconsolata,monospace} body.dark .status.redirect{color:#ecdb54} body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white} body.dark label{color:#f1f0ea} body.dark pre{color:#fff}</style>
    <script>
    document.addEventListener('DOMContentLoaded', (event) => {
      ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
    })
    </script>" >> ./$domain/$foldername/html_report.html
    echo '<link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css">
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css">
      <script type="text/javascript" src="https://code.jquery.com/jquery-3.3.1.js"></script>
    <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js"></script><script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js"></script>'>> ./$domain/$foldername/html_report.html
    echo '<script>$(document).ready( function () {
        $("#myTable").DataTable({
            "paging":   true,
            "ordering": true,
            "info":     false,
      "lengthMenu": [[10, 25, 50,100, -1], [10, 25, 50,100, "All"]],
        });
    } );</script></head>'>> ./$domain/$foldername/html_report.html



    echo '<body class="dark"><header class="site-header">
    <div class="site-title"><p>' >> ./$domain/$foldername/html_report.html
    echo "<a style=\"cursor: pointer\" onclick=\"localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\" title=\"Switch to light or dark theme\">🌓 Light|dark mode</a>
    </p>
    </div>
    </header>" >> ./$domain/$foldername/html_report.html

    echo '<div id="wrapper"><div id="container">' >> ./$domain/$foldername/html_report.html
    echo "<h2 class=\"post-title\" itemprop=\"name headline\">Hasil Pengintaian <a href=\"http://$domain\">$domain</a></h2>" >> ./$domain/$foldername/html_report.html
    echo "<p class=\"blog-description\">Dibuat oleh : Platform Validasi Keamanan dan Pengintaian Otomatis $(date) </p>" >> ./$domain/$foldername/html_report.html
    echo '<div class="container single-post-container">
    <article class="post-container-left" itemscope="" itemtype="http://schema.org/BlogPosting">
    <header class="post-header"></header>
    <div class="post-content clearfix" itemprop="articleBody">
    <h3>Total scanned subdomains</h3>
    <table id="myTable" class="stripe">
    <thead>
    <tr>
    <th>Subdomains</th>
    <th>Scanned Urls</th>
    </tr>
    </thead>
    <tbody>' >> ./$domain/$foldername/html_report.html


    cat ./$domain/$foldername/subdomain_live.txt |  sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g'  | while read nline; do
    echo "<tr>
    <td><a href='http://$nline'>$nline</a></td>
    <td><a href='./reports/$nline.txt'>$(cat ./$domain/$foldername/reports/$nline.txt | wc -l)</a></td>
    </tr>" >> ./$domain/$foldername/html_report.html
    done
    echo "</tbody></table>
    <div><h3>Kemungkinan Subdomain yang bisa diakuisisi</h3></div>
    <pre>" >> ./$domain/$foldername/html_report.html
    cat ./$domain/$foldername/domain_takeover.txt >> ./$domain/$foldername/html_report.html

    echo "</pre><div><h3>Data Terdahulu</h3></div>" >> ./$domain/$foldername/html_report.html
    echo "<table><tbody>" >> ./$domain/$foldername/html_report.html
    [ -s ./$domain/$foldername/interesting.txt ] && echo "<tr><td><a href='./interesting.txt'>interestingEXT Urls</a></td></tr>" >> ./$domain/$foldername/html_report.html
    echo "</tbody></table>" >> ./$domain/$foldername/html_report.html


    echo "<div><h3>Pengecekan Kerentanan</h3></div>
    <table><tbody>
    <tr><td><a href='./nuclei.txt'>nuclei scanner</a></td></tr>
    <tr><td><a href='./xss_result.txt'>Xss vuln</a></td></tr>
    <tr><td><a href='./listen_server.txt'>OOB SSRF vuln</a></td></tr>
    <tr><td><a href='./cors_result.txt'>CORS vuln</a></td></tr>
    <tr><td><a href='./prototype_pollution_result.txt'>Prototype Pollution vuln</a></td></tr>
    </tbody></table></div>" >> ./$domain/$foldername/html_report.html

    echo '</article><article class="post-container-right" itemscope="" itemtype="http://schema.org/BlogPosting">
    <header class="post-header">
    </header>
    <div class="post-content clearfix" itemprop="articleBody">' >> ./$domain/$foldername/html_report.html
    echo "<h3><a href='http://$server_ip:30200'>Melihat laporan hasil screenshot</a></h3>" >> ./$domain/$foldername/html_report.html
    echo "<h3>Dig Info</h3>
    <pre>
    $(dig $domain)
    </pre>" >> ./$domain/$foldername/html_report.html
    echo "<h3>Host Info</h3>
    <pre>
    $(host $domain)
    </pre>" >> ./$domain/$foldername/html_report.html
    echo "<h3>port scanning Results</h3>
    <pre> " >> ./$domain/$foldername/html_report.html
    naabu -host $domain -silent -ec 
    echo "</pre>
    </div></article></div>
    </div></div></body></html>" >> ./$domain/$foldername/html_report.html
}

#Fungsi untuk mengirimkan file zip

cleantemp(){
    rm ./$domain/$foldername/temp.txt
  	rm ./$domain/$foldername/tmp.txt
    rm ./$domain/$foldername/cleantemp.txt
    rm ./$domain/$foldername/cnames.txt
    rm ./$domain/$foldername/xss_raw_result.txt
}

main(){
if [ -z "${domain}" ]; then
domain=${subreport[1]}
foldername=${subreport[2]}
subd=${subreport[3]}
fi
  clear
  tagline
  echo "${green}Pengintaian pada domain $domain dimulai${reset}" | notify -silent
  if [ -d "./$domain" ]
  then
    echo "${red}Berikut yang didapatkan.${reset}"
  else
    mkdir ./$domain
  fi

  mkdir ./$domain/$foldername
  mkdir ./$domain/$foldername/reports/
  mkdir ./$domain/$foldername/screenshots/
  touch ./$domain/$foldername/crtsh.txt
  touch ./$domain/$foldername/shuffledns.txt
  touch ./$domain/$foldername/cnames.txt
  touch ./$domain/$foldername/domain_takeover.txt
  touch ./$domain/$foldername/temp.txt
  touch ./$domain/$foldername/tmp.txt
  touch ./$domain/$foldername/cleantemp.txt
  touch ./$domain/$foldername/interesting.txt
  touch ./$domain/$foldername/directory.txt
  touch ./$domain/$foldername/xss_raw_result.txt
  touch ./$domain/$foldername/gau_output.txt
  touch ./$domain/$foldername/sub_brute.txt
  touch ./$domain/$foldername/alldomains.txt
  touch ./$domain/$foldername/html_report.html
  
  cleantemp
  downloader
  oob_server
  mengintai $domain
  searchcrtsh $domain
  if [[ -n "$alt" ]]; then 
    permutatesubdomains $domain
  fi
  dnsprobing $domain
  subdomain_takeover $domain
	checkhttprobe $domain
  screenshots $domain
  getgau $domain
  get_interesting $domain
  if [[ -n "$brute" ]]; then 
    directory_bruteforce $domain
  fi
  if [[ -n "$nuclei" ]]; then 
    NucleiScanner $domain
  fi
  if [[ -n "$ssrf" ]]; then 
    SSRF_Scanner $domain
  fi
  if [[ -n "$xss" ]]; then 
    XSS_Scanner $domain
  fi
  if [[ -n "$cors" ]]; then 
    CORS_Scanner $domain
  fi
  if [[ -n "$prototype" ]]; then 
    Prototype_Pollution_Scanner $domain
  fi

  report $domain
  echo "${green}Validasi keamanan terhadap $domain Telah selesai${reset}" | notify -silent
  duration=$SECONDS
  echo "Roger! Validasi Keamanan dan Pengintaian Selesai dalam : $(($duration / 60)) menit dan $(($duration % 60)) detik." | notify -silent
  cleantemp
    # Fungsi menonaktfikan Listen Server
  kill_listen_server
#  echo "${green}Memulai screenshot ${reset}"
#  echo "${green}Untuk melihat GUI Screenshot silahkan buka link berikut http://$server_ip:30200 ${reset}" | notify -silent
#  cd ./$domain/$foldername/ &&  gowitness server -a $server_ip:30200
  stty sane
  tput sgr0
  zip_output
  exit 0
}

todate=$(date +%F-%T)
path=$(pwd)
foldername=$todate
source ~/.bash_profile
main $domain
