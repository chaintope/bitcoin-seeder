CXXFLAGS = -march=native -I/usr/local/opt/openssl/include
LDFLAGS = $(CXXFLAGS) -L/usr/local/opt/openssl/lib

ifeq (${DEBUG}, y)
  CXXFLAGS += -O0 -g3 -DDEBUG
else
  CXXFAGS += -O3 -g0
endif

dnsseed: dns.o tapyrus.o netbase.o protocol.o db.o main.o util.o
	g++ -pthread $(LDFLAGS) -o dnsseed dns.o tapyrus.o netbase.o protocol.o db.o main.o util.o -lcrypto

%.o: %.cpp *.h
	g++ -std=c++11 -pthread $(CXXFLAGS) -Wall -Wno-unused -Wno-sign-compare -Wno-reorder -Wno-comment -c -o $@ $<
