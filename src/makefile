CXX = g++
CXXFLAGS = -W -Wall -O2
DEBUGFLAGS = -W -Wall -g -O0
OBJECTS = ./netfilter-test.o ./ipv4hdr.o ./tcphdr.o ./ip.o
DOBJECTS = ./netfilter-test-D.o ./ipv4hdr-D.o ./tcphdr-D.o ./ip-D.o
TARGET = ../bin/netfilter-test
DTARGET = ../bin/netfilter-test-D
LIBS = -lnetfilter_queue

all: $(TARGET)
debug: $(DTARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

$(DTARGET): $(DOBJECTS)
	$(CXX) $(DEBUGFLAGS) -o $(@) $(^) $(LIBS)

netfilter-test.o: ./netfilter-test.cpp
ipv4hdr.o: ipv4hdr.cpp
tcphdr.o: tcphdr.cpp
ip.o: ip.cpp

netfilter-test-D.o: ./netfilter-test.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ipv4hdr-D.o: ipv4hdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
tcphdr-D.o: tcphdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ip-D.o: ip.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)

clean: 
	rm -f $(TARGET)
	rm -f $(DTARGET)
	rm -f *.o

.PHONY: all clean
