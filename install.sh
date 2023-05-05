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
################################################### INSTALASI #################################################
###############################################################################################################


sudo apt -y update
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
sudo python2 get-pip.py
export PATH=$PATH:/usr/local/bin
sudo apt-get install python3-pip
sudo apt-get install curl

sudo apt install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev
sudo apt install -y build-essential libssl-dev libffi-dev python3-dev
sudo apt install -y libcurl4-openssl-dev
sudo apt install -y python3-setuptools
sudo apt install -y python3-dnspython
sudo apt install -y libldns-dev
sudo apt install -y findutils
sudo apt install -y python-pip
sudo apt install -y libssl-dev
sudo apt install -y ruby-full
sudo apt install -y rename
sudo apt install -y xargs
sudo apt install -y git
sudo apt install -y jq

#Modul Instalasi Golang versi terbaru
if [[ -z "$GOPATH" ]]; then
    echo "Saya mendeteksi Golang belum terinstall, lakukan instalasi golang sekarang!"
    echo "Apakah Anda ingin menginstall? (ya/tidak): "
    read pilih
    case $pilih in
        ya)
            echo "Memulai instalasi Golang"
            wget https://dl.google.com/go/go1.20.3.linux-amd64.tar.gz
            sudo tar -xvf go1.20.3.linux-amd64.tar.gz
            sudo rm -rf /usr/local/go
            sudo mv go /usr/local
            export GOROOT=/usr/local/go
            export GOPATH=$HOME/go
            export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
            echo 'export GOROOT=/usr/local/go' >> ~/.bash_profile
            echo 'export GOPATH=$HOME/go' >> ~/.bash_profile
            echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bash_profile
            source ~/.bash_profile
            sleep 1
            ;;
        tidak)
            echo "Silahkan install golang terlebih dahulu, lalu mulai ulang"
            echo "Membatalkan instalasi"
            echo "Sampai Jumpa -_-"
            exit 1
            ;;
        *)
            echo "Pilihan tidak valid, silahkan pilih 'ya' atau 'tidak'"
            ;;
    esac
fi

#Repositori semua tools
mkdir ~/tools
cd ~/tools/

echo "Menginstall tool crobat"
go install  github.com/cgboal/sonarsearch/cmd/crobat@latest
echo "Selesai!"

echo "Menginstall tool subfinder"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "Selesai!"

echo "Menginstall tool assetfinder"
go install  github.com/tomnomnom/assetfinder@latest
echo "Selesai!"

echo "Menginstall tool dnsgen"
git clone https://github.com/ProjectAnte/dnsgen
cd dnsgen
pip3 install -r requirements.txt
sudo python3 setup.py install
cd ~/tools/
echo "Selesai!"

echo "Menginstall tool shuffledns"
go install  github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
echo "Selesai!"

echo "Menginstall tool massdns"
git clone https://github.com/blechschmidt/massdns.git
cd ~/tools/massdns
make
cd ~/tools/
echo "Selesai!"

echo "Menginstall tool gowitness"
go install github.com/sensepost/gowitness@latest
echo "Selesai!"

echo "Menginstall tool waybackurls"
go install github.com/tomnomnom/waybackurls@latest
echo "Selesai!"

echo "Menginstall tool httpx"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
echo "Selesai!"

echo "Menginstall tool feroxbuster"
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
echo "Selesai!"

echo "Menginstall tool ffuf"
go install github.com/ffuf/ffuf@latest
echo "Selesai!"

echo "Menginstall tool gf"
go install github.com/tomnomnom/gf@latest
echo "Selesai!"

echo "Menginstall tool  Gf-Patterns"
mkdir .gf
sudo cp -r $GOPATH/pkg/mod/github.com/tomnomnom/gf*/examples/ ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns
sudo mv ~/tools/Gf-Patterns/*.json ~/.gf
echo "Selesai!"


echo "Menginstall tool sqlmap"
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd ~/tools/
echo "Selesai!"


echo "Menginstall tool naabu"
sudo apt install -y libpcap-dev
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
echo "Selesai!"

echo "Menginstall tool unfurl"
go install github.com/tomnomnom/unfurl@latest
echo "Selesai!"

echo "Menginstall tool notify"
go install github.com/projectdiscovery/notify/cmd/notify@latest
echo "Selesai!"

echo "Menginstall tool nuclei"
go install  github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
echo "Selesai!"

echo "Menginstall tool CorsMe"
go install github.com/shivangx01b/CorsMe@latest
echo "Selesai!"

echo "Menginstall tool ppmap"
go install github.com/kleiton0x00/ppmap@latest
echo "Selesai!"

echo "Menginstall tool dalfox"
go install github.com/hahwul/dalfox/v2@latest
echo "Selesai!"

echo "Menginstall tool ParamSpider"
git clone https://github.com/devanshbatham/ParamSpider
cd ParamSpider
pip3 install -r requirements.txt
cd ~/tools/
echo "Selesai!"

echo "Menginstall tool qsreplace"
go install github.com/tomnomnom/qsreplace@latest
echo "Selesai!"

echo "Menginstall tool interactsh"
go install  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
echo "Selesai!"

echo "Mengunduh direktori Seclists"
cd ~/tools/
git clone https://github.com/danielmiessler/SecLists.git
cd ~/tools/SecLists/Discovery/DNS/

cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt
cd ~/tools/
echo "Selesai!"

sudo pip3 install urllib3==1.23
sudo pip3 install requests

echo -e "\n\n\n\n\n\n\n\n\n\n\nBerhasil! Semua Tools dan Library telah terinstall dan diperbarui, ~/tools"
ls -la
