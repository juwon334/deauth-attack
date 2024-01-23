LDLIBS += -lpcap

all: DeauthAttack

airodump_on: DeauthAttack.cpp

clean:
	rm -f DeauthAttack *.o