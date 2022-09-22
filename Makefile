wine_path='${HOME}/.steam/steam/steamapps/common/Proton - Experimental/files/bin/wine'

all: scanner

scanner: 
	gcc -Wall -o scanner scanner.c -lssl -lcrypto

scanner-win.exe:
	x86_64-w64-mingw32-g++ -Wall -o scanner-win.exe scanner-win.c -lssl -lcrypto -lws2_32

clean:
	rm scanner scanner-win.exe

run: 
	sudo ./scanner `cat guest-token.txt`

run-win:
	sudo ${wine_path} scanner-win.exe `cat guest-token.txt`