cc = gcc
cc_win = x86_64-w64-mingw32-g++

libs = -lssl -lcrypto -lpthread
libs_win = -lssl -lcrypto -lws2_32

run_args = `cat guest-token.txt`

# wine_path = '${HOME}/.steam/steam/steamapps/common/Proton - Experimental/files/bin/wine'

all: scanner scanner-win.exe

scanner: 
	${cc} -Wall -DSCAN_LINUX -o $@ scanner.c ${libs}

scanner-win.exe:
	${cc_win} -Wall -DSCAN_WIN -o $@ scanner-win.c ${libs_win}

clean:
	rm scanner scanner-win.exe

run: scanner
	sudo ./scanner ${run_args}

run-win: scanner-win.exe
	sudo wine scanner-win.exe ${run_args}