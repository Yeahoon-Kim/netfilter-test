CXX = g++
CXXFLAGS = -W -Wall -O2
OBJECTS = ./netfilter-test.o ./ipv4hdr.o ./tcphdr.o
TARGET = ../bin/netfilter-test
LIBS = -lnetfilter_queue

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

netfilter-test.o: ./netfilter-test.cpp
ipv4hdr.o: ipv4hdr.cpp
tcphdr.o: tcphdr.cpp

clean: 
	rm -f $(TARGET)
	rm -f *.o

.PHONY: all clean
