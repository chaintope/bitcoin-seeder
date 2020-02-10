# export OPENSSL_PREFIX=/usr/local/opt/openssl
# make
#   or
# make OPENSSL_PREFIX=/usr/local/opt/openssl
CXXFLAGS = -march=native -I${OPENSSL_PREFIX}/include
LDFLAGS = $(CXXFLAGS) -L${OPENSSL_PREFIX}/lib

# make DEBUG=y OPENSSL_PREFIX=/usr/local/opt/openssl
ifeq (${DEBUG}, y)
  CXXFLAGS += -O0 -g3 -DDEBUG
else
  CXXFAGS += -O3 -g0
endif

dnsseed: dns.o tapyrus.o netbase.o protocol.o db.o main.o util.o
	g++ -pthread $(LDFLAGS) -o dnsseed dns.o tapyrus.o netbase.o protocol.o db.o main.o util.o -lcrypto

%.o: %.cpp *.h
	g++ -std=c++11 -pthread $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<
