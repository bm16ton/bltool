CC := gcc
LIB_DIRECTORY := -L/usr/lib/x86_64-linux-gnu
INC_DIRECTORY := -I/usr/include/bluetooth -I/usr/include 
LIB := /usr/lib/x86_64-linux-gnu/libbluetooth.so.3
CFLAGS := -Wall -fPIC

.c.o:
	$(CC) $(INC_DIRECTORY) $(CFLAGS) -c $<

all:
	make tool
	make lib

tool:   bletool.o
	gcc -fPIC -o  bletool $(INC_DIRECTORY) $(LIB_DIRECTORY) $< -lbluetooth

lib:    bletool.o
	gcc $(CFLAGS)  -shared -o libbletool.so $< $(LIB)
	install -m 644 libbletool.so ../

clean:
	rm -f bletool bletool.o libbletool.o libbletool.so


$(shell sudo setcap 'cap_net_raw,cap_net_admin+eip' bletool)
