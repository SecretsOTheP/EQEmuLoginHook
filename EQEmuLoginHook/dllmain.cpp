// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "detours.h"
#include <WinSock.h>
#include <string>
#include <WinUser.h>
#include "gammaramp.h"
#pragma comment (lib, "detours.lib")
#pragma comment(lib,"wsock32.lib")
void ApplyHooksToModule(LPCSTR moduleName);
HINSTANCE hLThis = 0;
HINSTANCE hL = 0;
FARPROC p[75] = {0};
typedef signed int (__cdecl* ExecuteEverQuest_t)(int a1);
ExecuteEverQuest_t return_ExecuteEQ;
bool LoadedMainModule = false;
typedef signed int(__cdecl* ProcessGameEvents_t)();
ProcessGameEvents_t return_ProcessGameEvents;
typedef LRESULT (__stdcall* EverQuest_wndProc_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
EverQuest_wndProc_t return_EverQuest_WndProc;
typedef LONG (__stdcall* SetWindowLong_t)(HWND hWnd, int nIndex, LONG dwNewLong);
SetWindowLong_t return_SetWindowLong;

typedef int(__stdcall* SetGamma_t)(float a1);
SetGamma_t return_SetGamma;

typedef BOOL (__stdcall* SetWindowPos_t)(_In_     HWND hWnd,
	_In_opt_ HWND hWndInsertAfter,
	_In_     int  X,
	_In_     int  Y,
	_In_     int  cx,
	_In_     int  cy,
	_In_     UINT uFlags);
SetWindowPos_t return_SetWindowPos;

typedef HWND (__stdcall* CreateWindowExA_t)(DWORD     dwExStyle,
 LPCSTR   lpClassName,
 LPCSTR   lpWindowName,
 DWORD     dwStyle,
 int       x,
 int       y,
 int       nWidth,
 int       nHeight,
 HWND      hWndParent,
 HMENU     hMenu,
 HINSTANCE hInstance,
 LPVOID    lpParam);
CreateWindowExA_t return_CreateWindowExA;

typedef bool(__stdcall* ShowWindow_t)(HWND hWnd, int nCmdShow);
ShowWindow_t return_ShowWindow;

int FullScreenWindowed = 0;

HWND g_hWnd = NULL;

#ifdef EQMAC
DWORD o_ProcessGameEvents = 0x0055AFE2;
DWORD o_EverQuest_WndProc = 0x0055A4F4;
DWORD o_CEverQuest = 0x00809478;
DWORD o_DxFlushKeyboard = 0x0055AFB3;
DWORD o_AdjustGamma = 0x004A94F5;
#else //trilogy
DWORD o_ProcessGameEvents = 0x004EB0E0;
DWORD o_EverQuest_WndProc = 0x004EA74E;
DWORD o_CEverQuest = 0x006EFE2C;
DWORD o_DxFlushKeyboard = 0x0055AFB3;
DWORD o_AdjustGamma = 0x0040AF4F;
#endif


void PatchBytes(void * lpAddress, const char * szBytes, int nLen)
{
	// Needed by VirtualProtect.
	DWORD dwBack = 0;
	VirtualProtect(lpAddress, nLen, PAGE_READWRITE, &dwBack);

	// Write Byte-After-Byte.
	for (int i = 0; i < nLen; i++)
		*(BYTE *)((DWORD)lpAddress + i) = szBytes[i];

	// Restore old protection.
	VirtualProtect(lpAddress, nLen, dwBack, &dwBack);
}


std::string GetAndWriteKeyValueString(const char* Key, const char* Default)
{
	char curKey[256];
	memset(curKey, 0, 256);

	char curDirectory[MAX_PATH];


	GetCurrentDirectoryA(MAX_PATH, curDirectory);

	std::string dir = std::string(curDirectory) + std::string("\\eqw2.ini");

	DWORD error = GetPrivateProfileStringA("EQW2", Key, Default, curKey, 256, dir.c_str());
	if (GetLastError())
	{
		WritePrivateProfileStringA("EQW2", Key, Default, dir.c_str());
		return std::string(Default);
	}
	return std::string(curKey);
}

//Retrieves variables passed from EQ Client parameters ex; "C:\everquest\eqgame.exe" patchme /server:127.0.0.1 /ticket:Password /login:AccountName

/*
signed int __cdecl ExecuteEverQuest_Hook(int a1)
{
	memcpy((char*)CONST_ADDR_ACCOUNT, (const char*)CONST_ADDR_SENT_ACCOUNT, 18); //Account - max 18 length.
	memcpy((char*)CONST_ADDR_PASSWORD, (const char*)CONST_ADDR_SENT_LPASSWORD, 15); //Password - max 15 length.
	return return_ExecuteEQ(a1);
}*/

// Structure used to communicate data from and to enumeration procedure
struct EnumData {
	DWORD dwProcessId;
	HWND hWnd;
};

// Application-defined callback for EnumWindows
BOOL CALLBACK EnumProc(HWND hWnd, LPARAM lParam) {
	// Retrieve storage location for communication data
	EnumData& ed = *(EnumData*)lParam;
	DWORD dwProcessId = 0x0;
	// Query process ID for hWnd
	GetWindowThreadProcessId(hWnd, &dwProcessId);
	// Apply filter - if you want to implement additional restrictions,
	// this is the place to do so.
	if (ed.dwProcessId == dwProcessId) {
		// Found a window matching the process ID
		ed.hWnd = hWnd;
		// Report success
		SetLastError(ERROR_SUCCESS);
		// Stop enumeration
		return FALSE;
	}
	// Continue enumeration
	return TRUE;
}

// Main entry
HWND FindWindowFromProcessId(DWORD dwProcessId) {
	EnumData ed = { dwProcessId };
	if (!EnumWindows(EnumProc, (LPARAM)&ed) &&
		(GetLastError() == ERROR_SUCCESS)) {
		return ed.hWnd;
	}
	return NULL;
}


void __cdecl ResetMouseFlags() {

#ifdef EQMAC
	DWORD ptr = *(DWORD *)0x00809DB4;
	if (ptr)
	{
		*(BYTE*)(ptr + 85) = 0;
		*(BYTE*)(ptr + 86) = 0;
		*(BYTE*)(ptr + 87) = 0;
		*(BYTE*)(ptr + 88) = 0;
	}

	*(DWORD*)0x00809320 = 0;
	*(DWORD*)0x0080931C = 0;
	*(DWORD*)0x00809324 = 0;
	*(DWORD*)0x00809328 = 0;
	*(DWORD*)0x0080932C = 0;
#else
	((int(__cdecl*)())0x004E878C)();
#endif
}
// Helper method for convenience
HWND FindWindowFromProcess(HANDLE hProcess) {
	return FindWindowFromProcessId(GetProcessId(hProcess));
}


bool g_bFocus = false;

void ProcessHotkey(int hotKeyID)
{

	std::string win1Title = GetAndWriteKeyValueString("Client1Title", "Client1");
	std::string win2Title = GetAndWriteKeyValueString("Client2Title", "Client2");
	std::string win3Title = GetAndWriteKeyValueString("Client3Title", "Client3");
	std::string win4Title = GetAndWriteKeyValueString("Client4Title", "Client4");
	HWND hwnd = NULL;
	switch (hotKeyID)
	{
	case 0:
	{
		hwnd = FindWindowA(NULL, win1Title.c_str());
		if (hwnd)
		{
			SetForegroundWindow(hwnd);
		}
		break;
	}
	case 1:
	{
		hwnd = FindWindowA(NULL, win2Title.c_str());
		if (hwnd)
		{
			SetForegroundWindow(hwnd);
		}
		break;
	}
	case 2:
	{
		hwnd = FindWindowA(NULL, win1Title.c_str());
		if (hwnd)
		{
			SetForegroundWindow(hwnd);
		}
		break;
	}
	case 3:
	{
		hwnd = FindWindowA(NULL, win1Title.c_str());
		if (hwnd)
		{
			SetForegroundWindow(hwnd);
		}
		break;
	}
	default:
	{
		break;
	}
	}

}

struct RESOLUTION
{
	DWORD width;
	DWORD height;
	DWORD refresh;
	DWORD bpp;
};


int WINAPI EverQuest_wndProc_Hook(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{

	g_hWnd = hWnd;

	if (*(DWORD*)o_CEverQuest)
	{

		if (WM_WINDOWPOSCHANGED == Msg || WM_WINDOWPOSCHANGING == Msg || WM_NCCALCSIZE == Msg)
		{
			return 0;
		}

		if (WM_SYSCOMMAND == Msg)
		{
			if (wParam == SC_MINIMIZE)
			{
				return 0;
			}
		}

		//if (WM_HOTKEY == Msg)
		//{
		//	HWND oWnd = FindWindowFromProcess((HANDLE)GetCurrentProcess());

		//	HWND hwnd = GetForegroundWindow();

		//	if (!hwnd || hwnd != (HWND)oWnd)
		//	{
		//		ResetMouseFlags();
		//		((int(__cdecl*)())0x0055AFB3)();
		//		while (ShowCursor(TRUE) < 0);
		//		g_bFocus = false;
		//		ProcessHotkey(wParam);
		//	}
		//	return 0;
		//}

		if (WM_ACTIVATE == Msg || WM_ACTIVATEAPP == Msg)
		{
			HWND hwnd = FindWindowFromProcess((HANDLE)GetCurrentProcess());
			if (wParam)
			{
				if (!FullScreenWindowed)
					return_ShowWindow(hwnd, 1);
				else
					return_ShowWindow(hwnd, 3);
				
#ifdef EQMAC
				((int(__cdecl*)())0x0055AFB3)();
#else
				((int(__cdecl*)())0x004EB0B1)();
#endif
				ResetMouseFlags();
				while (ShowCursor(FALSE) >= 0);
			}
			else
			{
				ResetMouseFlags();
#ifdef EQMAC
				((int(__cdecl*)())0x0055AFB3)();
#else
				((int(__cdecl*)())0x004EB0B1)();
#endif
				while (ShowCursor(TRUE) < 0);
			}

			return return_EverQuest_WndProc(hWnd, Msg, wParam, lParam);
		}
	}

	return return_EverQuest_WndProc(hWnd, Msg, wParam, lParam);
}

bool setResolution = false;



	DWORD resx =0;
	DWORD resy = 0;
	DWORD bpp = 0;
	DWORD refresh = 0;


int __cdecl ProcessGameEvents_Hook() {  //55AFB3



	HWND oWnd = FindWindowFromProcess((HANDLE)GetCurrentProcess());

	HWND hwnd = GetForegroundWindow();

	if (!hwnd || hwnd != (HWND)oWnd)
	{
		ResetMouseFlags();

#ifdef EQMAC
		((int (__cdecl*)())0x0055AFB3)();
#else
		((int(__cdecl*)())0x004EB0B1)();
#endif
		while (ShowCursor(TRUE) < 0);
		g_bFocus = false;
		return 0;
	}

	g_hWnd = oWnd;

	if (!g_bFocus)
	{		
		
		
		if(*(DWORD*)(0x007F97D0) != 0 && setResolution == false)
		{

			DWORD ptr = *(DWORD*)(0x007F97D0);
			
			resx = *(DWORD*)(ptr + 0x7A28);
			resy = *(DWORD*)(ptr + 0x7A2C);
			bpp = *(DWORD*)(ptr + 0x7A20);
			refresh = *(DWORD*)(ptr + 0x7A30);
			setResolution = true;
		}
		else
		{
			*(DWORD*)0x005FE990 = resx;
			*(DWORD*)0x005FE994 = resy;
			*(DWORD*)0x005FE998 = bpp;
			*(DWORD*)0x0063AE8C = refresh;
			((int(__cdecl*)())0x0043BBE2)();
		}


#ifdef EQMAC
		((int(__cdecl*)())0x0055AFB3)();
#else
		((int(__cdecl*)())0x004EB0B1)();
#endif
		ResetMouseFlags();
		while (ShowCursor(FALSE) >= 0);
		g_bFocus = true;
	}

	return return_ProcessGameEvents();
}

signed int __cdecl FillInLoginHook()
{
  return 1;
}

bool WINAPI SetWindowTextHook(HWND hWnd, LPCSTR lpString)
{
	return 1;
}

int __stdcall SetGammaHook(float a1)
{
	CGammaRamp ramp;
	WORD UseGamma = atoi(GetAndWriteKeyValueString("UseGammaSlider", "1").c_str());
	if(UseGamma)
		ramp.SetBrightness(NULL, (int)(a1 * 100.f));
	return 0;
}

#ifdef EQMAC
#else
bool WINAPI SetWindowPosHook(HWND hWnd,
HWND hWndInsertAfter,
int  X,
int  Y,
int  cx,
int  cy,
UINT uFlags)
{
	return 1;
}
#endif

bool WINAPI ShowWindowHook(HWND hWnd, int nCmdShow)
{

	if (nCmdShow == 0)
		return return_ShowWindow(hWnd, 0);

	if (FullScreenWindowed)
		return return_ShowWindow(hWnd, 3);

	if (nCmdShow == 3 && !FullScreenWindowed)
	{
		return return_ShowWindow(hWnd, 1);
	}

	return return_ShowWindow(hWnd, nCmdShow);
}


LONG WINAPI SetWindowLongHook(HWND hWnd, int nIndex, LONG dwNewLong)
{
	if (GWL_STYLE == nIndex && FullScreenWindowed)
	{
		dwNewLong &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZE | WS_MAXIMIZE | WS_SYSMENU);
		LONG retval = return_SetWindowLong(hWnd, nIndex, dwNewLong);
		return_ShowWindow(hWnd, SW_SHOW);
		return retval;
	}

	return return_SetWindowLong(hWnd, nIndex, dwNewLong);
}



char g_wTitle[MAX_PATH];

std::string winTitle;
int XOffset = 0;
int YOffset = 0;
int X = 0;
int Y = 0;
bool registerme = false;

HWND WINAPI CreateWindowExAHook(DWORD     dwExStyle,
	_In_opt_ LPCSTR   lpClassName,
	_In_opt_ LPCSTR   lpWindowName,
	_In_     DWORD     dwStyle,
	_In_     int       x,
	_In_     int       y,
	_In_     int       nWidth,
	_In_     int       nHeight,
	_In_opt_ HWND      hWndParent,
	_In_opt_ HMENU     hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID    lpParam)
{
	int Hotkey1 = atoi(GetAndWriteKeyValueString("Client1Key", "73").c_str());
	int Hotkey2 = atoi(GetAndWriteKeyValueString("Client2Key", "74").c_str());
	int Hotkey3 = atoi(GetAndWriteKeyValueString("Client3Key", "75").c_str());
	int Hotkey4 = atoi(GetAndWriteKeyValueString("Client4Key", "76").c_str());


	FullScreenWindowed = atoi(GetAndWriteKeyValueString("FullScreenWindowed", "0").c_str());

	int HotkeyMod1 = atoi(GetAndWriteKeyValueString("Client1Modifier", "4").c_str());
	int HotkeyMod2 = atoi(GetAndWriteKeyValueString("Client2Modifier", "4").c_str());
	int HotkeyMod3 = atoi(GetAndWriteKeyValueString("Client3Modifier", "4").c_str());
	int HotkeyMod4 = atoi(GetAndWriteKeyValueString("Client4Modifier", "4").c_str());
	std::string tmpTitle = winTitle;

	DWORD tmpStyle = dwStyle;

	if (FullScreenWindowed)
		tmpStyle &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZE | WS_MAXIMIZE | WS_SYSMENU);

	int X1 = atoi(GetAndWriteKeyValueString("Client1X", "800").c_str());
	int X2 = atoi(GetAndWriteKeyValueString("Client2X", "800").c_str());
	int X3 = atoi(GetAndWriteKeyValueString("Client3X", "800").c_str());
	int X4 = atoi(GetAndWriteKeyValueString("Client4X", "800").c_str());

	int Y1 = atoi(GetAndWriteKeyValueString("Client1Y", "600").c_str());
	int Y2 = atoi(GetAndWriteKeyValueString("Client2Y", "600").c_str());
	int Y3 = atoi(GetAndWriteKeyValueString("Client3Y", "600").c_str());
	int Y4 = atoi(GetAndWriteKeyValueString("Client4Y", "600").c_str());


	if (g_hWnd == 0)
	{

		std::string win1Title = GetAndWriteKeyValueString("Client1Title", "Client1").c_str();
		std::string win2Title = GetAndWriteKeyValueString("Client2Title", "Client2").c_str();
		std::string win3Title = GetAndWriteKeyValueString("Client3Title", "Client3").c_str();
		std::string win4Title = GetAndWriteKeyValueString("Client4Title", "Client4").c_str();

		int XOffset1 = atoi(GetAndWriteKeyValueString("Client1XOffset", "0").c_str());
		int XOffset2 = atoi(GetAndWriteKeyValueString("Client2XOffset", "0").c_str());
		int XOffset3 = atoi(GetAndWriteKeyValueString("Client3XOffset", "0").c_str());
		int XOffset4 = atoi(GetAndWriteKeyValueString("Client4XOffset", "0").c_str());

		int YOffset1 = atoi(GetAndWriteKeyValueString("Client1YOffset", "0").c_str());
		int YOffset2 = atoi(GetAndWriteKeyValueString("Client2YOffset", "0").c_str());
		int YOffset3 = atoi(GetAndWriteKeyValueString("Client3YOffset", "0").c_str());
		int YOffset4 = atoi(GetAndWriteKeyValueString("Client4YOffset", "0").c_str());


		tmpTitle = win1Title;
		int XOffset = XOffset1;
		int YOffset = YOffset1;
		X = X1;
		Y = Y1;
		bool bFoundFree = false;

		if (!FindWindowA(NULL, win1Title.c_str()) && !bFoundFree)
		{
			XOffset = XOffset1;
			YOffset = YOffset1;
			winTitle = win1Title;
			tmpTitle = win1Title;
			X = X1;
			Y = Y1;
			bFoundFree = true;
		}

		if (!FindWindowA(NULL, win2Title.c_str()) && !bFoundFree)
		{
			XOffset = XOffset2;
			YOffset = YOffset2;
			tmpTitle = win2Title;
			winTitle = win2Title;
			X = X2;
			Y = Y2;
			bFoundFree = true;
		}

		if (!FindWindowA(NULL, win3Title.c_str()) && !bFoundFree)
		{
			XOffset = XOffset3;
			YOffset = YOffset3;
			tmpTitle = win3Title;
			winTitle = win3Title;
			X = X3;
			Y = Y3;
			bFoundFree = true;
		}

		if (!FindWindowA(NULL, win4Title.c_str()) && !bFoundFree)
		{
			XOffset = XOffset4;
			YOffset = YOffset4;
			tmpTitle = win4Title;
			winTitle = win4Title;
			X = X4;
			Y = X4;
			bFoundFree = true;
		}
#ifndef EQMAC
		g_hWnd = return_CreateWindowExA(dwExStyle, lpClassName, tmpTitle.c_str(), tmpStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
#else
		g_hWnd = return_CreateWindowExA(dwExStyle, lpClassName, tmpTitle.c_str(), tmpStyle, XOffset, YOffset, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
#endif
	}
	else
	{
		tmpTitle.append("-LS");
#ifndef EQMAC
		g_hWnd = return_CreateWindowExA(dwExStyle, lpClassName, tmpTitle.c_str(), tmpStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
#else
		g_hWnd = return_CreateWindowExA(dwExStyle, lpClassName, tmpTitle.c_str(), tmpStyle, XOffset, YOffset, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
#endif
	}

	return g_hWnd;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		hLThis = hModule;
        char system[MAX_PATH];
        GetSystemDirectoryA(system,sizeof(system));
        strcat_s(system,"\\WSOCK32.dll");
        hL = LoadLibraryA(system);
        if (!hL) return false;

	//	return_ExecuteEQ = (ExecuteEverQuest_t)DetourFunction((PBYTE)0x00559F7A, (PBYTE)ExecuteEverQuest_Hook);
		return_ProcessGameEvents = (ProcessGameEvents_t)DetourFunction((PBYTE)o_ProcessGameEvents, (PBYTE)ProcessGameEvents_Hook);
		return_EverQuest_WndProc = (EverQuest_wndProc_t)DetourFunction((PBYTE)o_EverQuest_WndProc, (PBYTE)EverQuest_wndProc_Hook);
		return_CreateWindowExA = (CreateWindowExA_t)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("user32.dll"), "CreateWindowExA"), (PBYTE)CreateWindowExAHook);
		return_ShowWindow = (ShowWindow_t)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("user32.dll"), "ShowWindow"), (PBYTE)ShowWindowHook);
		return_SetWindowLong = (SetWindowLong_t)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("user32.dll"), "SetWindowLongA"), (PBYTE)SetWindowLongHook);
		DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("user32.dll"),"SetWindowTextA"), (PBYTE)SetWindowTextHook);
		return_SetGamma = (SetGamma_t)DetourFunction((PBYTE)o_AdjustGamma, (PBYTE)SetGammaHook);

#ifdef EQMAC
		//TODO: Move binary patches over.

#else
		PatchBytes((void*)0x00409539, "\x00", 1);
		PatchBytes((void*)0x004923E0, "\x90\x90\xEB\x63", 4);
		return_SetWindowPos = (SetWindowPos_t)DetourFunction((PBYTE)GetProcAddress(GetModuleHandleA("user32.dll"), "SetWindowPos"), (PBYTE)SetWindowPosHook);
#endif

        p[0] = GetProcAddress(hL,"AcceptEx");
        p[1] = GetProcAddress(hL,"EnumProtocolsA");
        p[2] = GetProcAddress(hL,"EnumProtocolsW");
        p[3] = GetProcAddress(hL,"GetAcceptExSockaddrs");
        p[4] = GetProcAddress(hL,"GetAddressByNameA");
        p[5] = GetProcAddress(hL,"GetAddressByNameW");
        p[6] = GetProcAddress(hL,"GetNameByTypeA");
        p[7] = GetProcAddress(hL,"GetNameByTypeW");
        p[8] = GetProcAddress(hL,"GetServiceA");
        p[9] = GetProcAddress(hL,"GetServiceW");
        p[10] = GetProcAddress(hL,"GetTypeByNameA");
        p[11] = GetProcAddress(hL,"GetTypeByNameW");
        p[12] = GetProcAddress(hL,"MigrateWinsockConfiguration");
        p[13] = GetProcAddress(hL,"NPLoadNameSpaces");
        p[14] = GetProcAddress(hL,"SetServiceA");
        p[15] = GetProcAddress(hL,"SetServiceW");
        p[16] = GetProcAddress(hL,"TransmitFile");
        p[17] = GetProcAddress(hL,"WEP");
        p[18] = GetProcAddress(hL,"WSAAsyncGetHostByAddr");
        p[19] = GetProcAddress(hL,"WSAAsyncGetHostByName");
        p[20] = GetProcAddress(hL,"WSAAsyncGetProtoByName");
        p[21] = GetProcAddress(hL,"WSAAsyncGetProtoByNumber");
        p[22] = GetProcAddress(hL,"WSAAsyncGetServByName");
        p[23] = GetProcAddress(hL,"WSAAsyncGetServByPort");
        p[24] = GetProcAddress(hL,"WSAAsyncSelect");
        p[25] = GetProcAddress(hL,"WSACancelAsyncRequest");
        p[26] = GetProcAddress(hL,"WSACancelBlockingCall");
        p[27] = GetProcAddress(hL,"WSACleanup");
        p[28] = GetProcAddress(hL,"WSAGetLastError");
        p[29] = GetProcAddress(hL,"WSAIsBlocking");
        p[30] = GetProcAddress(hL,"WSARecvEx");
        p[31] = GetProcAddress(hL,"WSASetBlockingHook");
        p[32] = GetProcAddress(hL,"WSASetLastError");
        p[33] = GetProcAddress(hL,"WSAStartup");
        p[34] = GetProcAddress(hL,"WSAUnhookBlockingHook");
        p[35] = GetProcAddress(hL,"WSApSetPostRoutine");
        p[36] = GetProcAddress(hL,"__WSAFDIsSet");
        p[37] = GetProcAddress(hL,"accept");
        p[38] = GetProcAddress(hL,"bind");
        p[39] = GetProcAddress(hL,"closesocket");
        p[40] = GetProcAddress(hL,"connect");
        p[41] = GetProcAddress(hL,"dn_expand");
        p[42] = GetProcAddress(hL,"gethostbyaddr");
        p[43] = GetProcAddress(hL,"gethostbyname");
        p[44] = GetProcAddress(hL,"gethostname");
        p[45] = GetProcAddress(hL,"getnetbyname");
        p[46] = GetProcAddress(hL,"getpeername");
        p[47] = GetProcAddress(hL,"getprotobyname");
        p[48] = GetProcAddress(hL,"getprotobynumber");
        p[49] = GetProcAddress(hL,"getservbyname");
        p[50] = GetProcAddress(hL,"getservbyport");
        p[51] = GetProcAddress(hL,"getsockname");
        p[52] = GetProcAddress(hL,"getsockopt");
        p[53] = GetProcAddress(hL,"htonl");
        p[54] = GetProcAddress(hL,"htons");
        p[55] = GetProcAddress(hL,"inet_addr");
        p[56] = GetProcAddress(hL,"inet_network");
        p[57] = GetProcAddress(hL,"inet_ntoa");
        p[58] = GetProcAddress(hL,"ioctlsocket");
        p[59] = GetProcAddress(hL,"listen");
        p[60] = GetProcAddress(hL,"ntohl");
        p[61] = GetProcAddress(hL,"ntohs");
        p[62] = GetProcAddress(hL,"rcmd");
        p[63] = GetProcAddress(hL,"recv");
        p[64] = GetProcAddress(hL,"recvfrom");
        p[65] = GetProcAddress(hL,"rexec");
        p[66] = GetProcAddress(hL,"rresvport");
        p[67] = GetProcAddress(hL,"s_perror");
        p[68] = GetProcAddress(hL,"select");
        p[69] = GetProcAddress(hL,"send");
        p[70] = GetProcAddress(hL,"sendto");
        p[71] = GetProcAddress(hL,"sethostname");
        p[72] = GetProcAddress(hL,"setsockopt");
        p[73] = GetProcAddress(hL,"shutdown");
        p[74] = GetProcAddress(hL,"socket");
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		FreeLibrary(hL);
		break;
	}
	return TRUE;
}


// AcceptEx
extern "C" __declspec(naked) void __stdcall __E__0__()
    {
    __asm
        {
        jmp p[0*4];
        }
    }

// EnumProtocolsA
extern "C" __declspec(naked) void __stdcall __E__1__()
    {
    __asm
        {
        jmp p[1*4];
        }
    }

// EnumProtocolsW
extern "C" __declspec(naked) void __stdcall __E__2__()
    {
    __asm
        {
        jmp p[2*4];
        }
    }

// GetAcceptExSockaddrs
extern "C" __declspec(naked) void __stdcall __E__3__()
    {
    __asm
        {
        jmp p[3*4];
        }
    }

// GetAddressByNameA
extern "C" __declspec(naked) void __stdcall __E__4__()
    {
    __asm
        {
        jmp p[4*4];
        }
    }

// GetAddressByNameW
extern "C" __declspec(naked) void __stdcall __E__5__()
    {
    __asm
        {
        jmp p[5*4];
        }
    }

// GetNameByTypeA
extern "C" __declspec(naked) void __stdcall __E__6__()
    {
    __asm
        {
        jmp p[6*4];
        }
    }

// GetNameByTypeW
extern "C" __declspec(naked) void __stdcall __E__7__()
    {
    __asm
        {
        jmp p[7*4];
        }
    }

// GetServiceA
extern "C" __declspec(naked) void __stdcall __E__8__()
    {
    __asm
        {
        jmp p[8*4];
        }
    }

// GetServiceW
extern "C" __declspec(naked) void __stdcall __E__9__()
    {
    __asm
        {
        jmp p[9*4];
        }
    }

// GetTypeByNameA
extern "C" __declspec(naked) void __stdcall __E__10__()
    {
    __asm
        {
        jmp p[10*4];
        }
    }

// GetTypeByNameW
extern "C" __declspec(naked) void __stdcall __E__11__()
    {
    __asm
        {
        jmp p[11*4];
        }
    }

// MigrateWinsockConfiguration
extern "C" __declspec(naked) void __stdcall __E__12__()
    {
    __asm
        {
        jmp p[12*4];
        }
    }

// NPLoadNameSpaces
extern "C" __declspec(naked) void __stdcall __E__13__()
    {
    __asm
        {
        jmp p[13*4];
        }
    }

// SetServiceA
extern "C" __declspec(naked) void __stdcall __E__14__()
    {
    __asm
        {
        jmp p[14*4];
        }
    }

// SetServiceW
extern "C" __declspec(naked) void __stdcall __E__15__()
    {
    __asm
        {
        jmp p[15*4];
        }
    }

// TransmitFile
extern "C" __declspec(naked) void __stdcall __E__16__()
    {
    __asm
        {
        jmp p[16*4];
        }
    }

// WEP
extern "C" __declspec(naked) void __stdcall __E__17__()
    {
    __asm
        {
        jmp p[17*4];
        }
    }

// WSAAsyncGetHostByAddr
extern "C" __declspec(naked) void __stdcall __E__18__()
    {
    __asm
        {
        jmp p[18*4];
        }
    }

// WSAAsyncGetHostByName
extern "C" __declspec(naked) void __stdcall __E__19__()
    {
    __asm
        {
        jmp p[19*4];
        }
    }

// WSAAsyncGetProtoByName
extern "C" __declspec(naked) void __stdcall __E__20__()
    {
    __asm
        {
        jmp p[20*4];
        }
    }

// WSAAsyncGetProtoByNumber
extern "C" __declspec(naked) void __stdcall __E__21__()
    {
    __asm
        {
        jmp p[21*4];
        }
    }

// WSAAsyncGetServByName
extern "C" __declspec(naked) void __stdcall __E__22__()
    {
    __asm
        {
        jmp p[22*4];
        }
    }

// WSAAsyncGetServByPort
extern "C" __declspec(naked) void __stdcall __E__23__()
    {
    __asm
        {
        jmp p[23*4];
        }
    }

// WSAAsyncSelect
extern "C" __declspec(naked) void __stdcall __E__24__()
    {
    __asm
        {
        jmp p[24*4];
        }
    }

// WSACancelAsyncRequest
extern "C" __declspec(naked) void __stdcall __E__25__()
    {
    __asm
        {
        jmp p[25*4];
        }
    }

// WSACancelBlockingCall
extern "C" __declspec(naked) void __stdcall __E__26__()
    {
    __asm
        {
        jmp p[26*4];
        }
    }

// WSACleanup
extern "C" __declspec(naked) void __stdcall __E__27__()
    {
    __asm
        {
        jmp p[27*4];
        }
    }

// WSAGetLastError
extern "C" __declspec(naked) void __stdcall __E__28__()
    {
    __asm
        {
        jmp p[28*4];
        }
    }

// WSAIsBlocking
extern "C" __declspec(naked) void __stdcall __E__29__()
    {
    __asm
        {
        jmp p[29*4];
        }
    }

// WSARecvEx
extern "C" __declspec(naked) void __stdcall __E__30__()
    {
    __asm
        {
        jmp p[30*4];
        }
    }

// WSASetBlockingHook
extern "C" __declspec(naked) void __stdcall __E__31__()
    {
    __asm
        {
        jmp p[31*4];
        }
    }

// WSASetLastError
extern "C" __declspec(naked) void __stdcall __E__32__()
    {
    __asm
        {
        jmp p[32*4];
        }
    }

// WSAStartup
extern "C" __declspec(naked) void __stdcall __E__33__()
    {
    __asm
        {
        jmp p[33*4];
        }
    }

// WSAUnhookBlockingHook
extern "C" __declspec(naked) void __stdcall __E__34__()
    {
    __asm
        {
        jmp p[34*4];
        }
    }

// WSApSetPostRoutine
extern "C" __declspec(naked) void __stdcall __E__35__()
    {
    __asm
        {
        jmp p[35*4];
        }
    }

// __WSAFDIsSet
extern "C" __declspec(naked) void __stdcall __E__36__()
    {
    __asm
        {
        jmp p[36*4];
        }
    }

// accept
extern "C" __declspec(naked) void __stdcall __E__37__()
    {
    __asm
        {
        jmp p[37*4];
        }
    }

// bind
extern "C" __declspec(naked) void __stdcall __E__38__()
    {
    __asm
        {
        jmp p[38*4];
        }
    }

// closesocket
extern "C" __declspec(naked) void __stdcall __E__39__()
    {
    __asm
        {
        jmp p[39*4];
        }
    }

// connect
extern "C" __declspec(naked) void __stdcall __E__40__()
    {
    __asm
        {
        jmp p[40*4];
        }
    }

// dn_expand
extern "C" __declspec(naked) void __stdcall __E__41__()
    {
    __asm
        {
        jmp p[41*4];
        }
    }

// gethostbyaddr
extern "C" __declspec(naked) void __stdcall __E__42__()
    {
    __asm
        {
        jmp p[42*4];
        }
    }

// gethostbyname
extern "C" __declspec(naked) void __stdcall __E__43__()
    {
    __asm
        {
        jmp p[43*4];
        }
    }

// gethostname
extern "C" __declspec(naked) void __stdcall __E__44__()
    {
    __asm
        {
        jmp p[44*4];
        }
    }

// getnetbyname
extern "C" __declspec(naked) void __stdcall __E__45__()
    {
    __asm
        {
        jmp p[45*4];
        }
    }

// getpeername
extern "C" __declspec(naked) void __stdcall __E__46__()
    {
    __asm
        {
        jmp p[46*4];
        }
    }

// getprotobyname
extern "C" __declspec(naked) void __stdcall __E__47__()
    {
    __asm
        {
        jmp p[47*4];
        }
    }

// getprotobynumber
extern "C" __declspec(naked) void __stdcall __E__48__()
    {
    __asm
        {
        jmp p[48*4];
        }
    }

// getservbyname
extern "C" __declspec(naked) void __stdcall __E__49__()
    {
    __asm
        {
        jmp p[49*4];
        }
    }

// getservbyport
extern "C" __declspec(naked) void __stdcall __E__50__()
    {
    __asm
        {
        jmp p[50*4];
        }
    }

// getsockname
extern "C" __declspec(naked) void __stdcall __E__51__()
    {
    __asm
        {
        jmp p[51*4];
        }
    }

// getsockopt
extern "C" __declspec(naked) void __stdcall __E__52__()
    {
    __asm
        {
        jmp p[52*4];
        }
    }

// htonl
extern "C" __declspec(naked) void __stdcall __E__53__()
    {
    __asm
        {
        jmp p[53*4];
        }
    }

// htons
extern "C" __declspec(naked) void __stdcall __E__54__()
    {
    __asm
        {
        jmp p[54*4];
        }
    }

// inet_addr
extern "C" __declspec(naked) void __stdcall __E__55__()
    {
    __asm
        {
        jmp p[55*4];
        }
    }

// inet_network
extern "C" __declspec(naked) void __stdcall __E__56__()
    {
    __asm
        {
        jmp p[56*4];
        }
    }

// inet_ntoa
extern "C" __declspec(naked) void __stdcall __E__57__()
    {
    __asm
        {
        jmp p[57*4];
        }
    }

// ioctlsocket
extern "C" __declspec(naked) void __stdcall __E__58__()
    {
    __asm
        {
        jmp p[58*4];
        }
    }

// listen
extern "C" __declspec(naked) void __stdcall __E__59__()
    {
    __asm
        {
        jmp p[59*4];
        }
    }

// ntohl
extern "C" __declspec(naked) void __stdcall __E__60__()
    {
    __asm
        {
        jmp p[60*4];
        }
    }

// ntohs
extern "C" __declspec(naked) void __stdcall __E__61__()
    {
    __asm
        {
        jmp p[61*4];
        }
    }

// rcmd
extern "C" __declspec(naked) void __stdcall __E__62__()
    {
    __asm
        {
        jmp p[62*4];
        }
    }

// recv
extern "C" __declspec(naked) void __stdcall __E__63__()
    {
    __asm
        {
        jmp p[63*4];
        }
    }

// recvfrom
extern "C" __declspec(naked) void __stdcall __E__64__()
    {
    __asm
        {
        jmp p[64*4];
        }
    }

// rexec
extern "C" __declspec(naked) void __stdcall __E__65__()
    {
    __asm
        {
        jmp p[65*4];
        }
    }

// rresvport
extern "C" __declspec(naked) void __stdcall __E__66__()
    {
    __asm
        {
        jmp p[66*4];
        }
    }

// s_perror
extern "C" __declspec(naked) void __stdcall __E__67__()
    {
    __asm
        {
        jmp p[67*4];
        }
    }

// select
extern "C" __declspec(naked) void __stdcall __E__68__()
    {
    __asm
        {
        jmp p[68*4];
        }
    }

// send
extern "C" __declspec(naked) void __stdcall __E__69__()
    {
    __asm
        {
        jmp p[69*4];
        }
    }

// sendto
extern "C" __declspec(naked) void __stdcall __E__70__()
    {
    __asm
        {
        jmp p[70*4];
        }
    }

// sethostname
extern "C" __declspec(naked) void __stdcall __E__71__()
    {
    __asm
        {
        jmp p[71*4];
        }
    }

// setsockopt
extern "C" __declspec(naked) void __stdcall __E__72__()
    {
    __asm
        {
        jmp p[72*4];
        }
    }

// shutdown
extern "C" __declspec(naked) void __stdcall __E__73__()
    {
    __asm
        {
        jmp p[73*4];
        }
    }

// socket
extern "C" __declspec(naked) void __stdcall __E__74__()
    {
    __asm
        {
        jmp p[74*4];
        }
    }  