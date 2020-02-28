# install necessary dev tools for make.
sudo apt update
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:bitcoin/bitcoin
sudo apt-get -y update
sudo apt-get -y install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3
sudo apt-get -y install libboost-all-dev
sudo apt-get install -y software-properties-common
sudo apt-get -y install libdb4.8-dev libdb4.8++-dev

# clone project
git clone https://github.com/chaintope/tapyrus-seeder
cd tapyrus-seeder

#clearn
rm -f tapyrusseed *.o

# build
make

# install
sudo cp ./tapyrusseed /usr/bin/tapyrusseed

