BOFNAME := fw_walk
CC_x64 := x86_64-w64-mingw32-g++
CC_x86 := i686-w64-mingw32-g++

all:
	$(CC_x64) -Wno-unused-variable -Wno-write-strings -o ../dist/$(BOFNAME).x64.o -c main.cpp -masm=intel

clean:
	rm -f ../dist/$(BOFNAME).x64.o
