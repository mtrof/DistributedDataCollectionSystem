#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <Windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <wchar.h>
#include <aclapi.h>
#include <sddl.h>
#include <lmcons.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

#pragma warning (disable: 4703)

#define LISTEN_PORT 9000

#define MAX_CLIENTS 100
#define CLIENT_TIME 300

#define RECV_BUF_SIZE 4096
#define SEND_BUF_SIZE 4096

struct client_ctx
{
	int socket;

	CHAR buf_recv[RECV_BUF_SIZE], buf_send[SEND_BUF_SIZE];

	unsigned int sz_recv, sz_send, sz_send_total;

	OVERLAPPED overlap_recv, overlap_send, overlap_cancel;

	DWORD flags_recv;
	DWORD time;

	HCRYPTPROV CSP_desc = 0;
	HCRYPTKEY pb_key_desc = 0;
	HCRYPTKEY sess_key_desc = 0;
};

struct acl
{
	std::string name;
	char* sid;
	DWORD mask;
	std::vector<std::string> ace;
	bool deny_ace;
	bool inherit;
};

struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

void add_accepted_conn()
{
	DWORD i = 0;
	for (; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			g_ctxs[i].time = clock();

			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0;
			struct sockaddr_in* remote_addr = 0;
			int local_addr_sz = 0;
			int remote_addr_sz = 0;

			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, 
				sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, 
				(struct sockaddr**)&local_addr, &local_addr_sz, 
				(struct sockaddr**)&remote_addr, &remote_addr_sz);

			if (remote_addr)
				ip = ntohl(remote_addr->sin_addr.s_addr);

			unsigned int ip1 = (ip >> 24) & 0xff;
			unsigned int ip2 = (ip >> 16) & 0xff;
			unsigned int ip3 = (ip >> 8) & 0xff;
			unsigned int ip4 = (ip) & 0xff;
			std::cout << "Connection " << i << " created, remote IP: ";
			std::cout << ip1 << "." << ip2 << "." << ip3 << "." << ip4;
			std::cout << std::endl;
			g_ctxs[i].socket = g_accepted_socket;
			
			if (CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0) == NULL)
			{
				std::cout << "CreateIoCompletionPort error: " << GetLastError() << std::endl;
				return;
			}
			
			schedule_read(i);
			return;
		}
	}

	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

void schedule_accept()
{
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, 
		sizeof(struct sockaddr_in) + 16, sizeof(struct	sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

bool is_string_recv(DWORD idx, int& len)
{
	DWORD i;
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			len = (int)(i + 1);
			return true;
		}
	}
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{
		len = sizeof(g_ctxs[idx].buf_recv);
		return true;
	}

	return true;
}

void crypt_init(int idx)
{
	if (!CryptAcquireContextW(&g_ctxs[idx].CSP_desc, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContextW(&g_ctxs[idx].CSP_desc, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			std::cout << "Error acquiring handle to key container!" << std::endl;
	}

	if (!CryptGenKey(g_ctxs[idx].CSP_desc, CALG_RC4, (CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT), &g_ctxs[idx].sess_key_desc))
		std::cout << "Error generating session key!" << std::endl;

	int i = 255;
	while(i >= 0 && g_ctxs[idx].buf_recv[i] == 0) i--;

	unsigned int len = (unsigned char)g_ctxs[idx].buf_recv[i];
	g_ctxs[idx].buf_recv[i] = 0;

	if (!CryptImportKey(g_ctxs[idx].CSP_desc, (BYTE*)g_ctxs[idx].buf_recv, len, 0, 0, &g_ctxs[idx].pb_key_desc))
		std::cout << "Error importing public key!" << std::endl;

	DWORD exp_len = 256;
	if (!CryptExportKey(g_ctxs[idx].sess_key_desc, g_ctxs[idx].pb_key_desc, SIMPLEBLOB, NULL, (BYTE*)g_ctxs[idx].buf_send, &exp_len))
		std::cout << "Error exporting session key!" << std::endl;
	
	g_ctxs[idx].buf_send[exp_len] = exp_len;
	g_ctxs[idx].sz_send_total = exp_len + 1;
}

void serve_client(DWORD idx)
{
	DWORD data_size = 0;
	if (g_ctxs[idx].CSP_desc != 0 && g_ctxs[idx].pb_key_desc != 0 && g_ctxs[idx].sess_key_desc != 0)
	{
		data_size = g_ctxs[idx].sz_recv;
		if (!CryptDecrypt(g_ctxs[idx].sess_key_desc, NULL, TRUE, NULL, (BYTE*)g_ctxs[idx].buf_recv, (DWORD*)&data_size))
			std::cout << "Decryption error! Error code: " << GetLastError() << std::endl;
	}

	if (data_size == 0)
	{
		crypt_init(idx);
		return;
	}

	char command = g_ctxs[idx].buf_recv[0];
	std::string arg = "";
	if (g_ctxs[idx].buf_recv[1] == ' ')
		arg = (char*)(g_ctxs[idx].buf_recv + 2);

	if (command == 'a')
	{
		DWORD buf_size = 100;
		CHAR version[100];
		HKEY hKey;

		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
		{
			RegQueryValueExA(hKey, "ProductName", NULL, NULL, (LPBYTE)version, &buf_size);
			strcpy(g_ctxs[idx].buf_send, version);
		}
	}
	else if (command == 'b')
	{
		DWORD len = 2048;
		auto time_now = std::chrono::system_clock::now();
		time_t time = std::chrono::system_clock::to_time_t(time_now);
		std::string times(std::ctime(&time));
		if (times[times.length() - 1] == '\n')
			times.erase(times.length() - 1);
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], times.c_str());
	}
	else if (command == 'c')
	{
		DWORD len = 2048;
		auto msecs = std::chrono::milliseconds(GetTickCount64());
		auto secs = std::chrono::duration_cast<std::chrono::seconds>(msecs);
		msecs -= std::chrono::duration_cast<std::chrono::milliseconds>(secs);
		auto mins = std::chrono::duration_cast<std::chrono::minutes>(secs);
		secs -= std::chrono::duration_cast<std::chrono::seconds>(mins);
		auto hour = std::chrono::duration_cast<std::chrono::hours>(mins);
		mins -= std::chrono::duration_cast<std::chrono::minutes>(hour);
		std::string res(std::to_string(hour.count()) + " hours "
			+ std::to_string(mins.count()) + " mins "
			+ std::to_string(secs.count()) + " secs "
			+ std::to_string(msecs.count()) + " msecs");
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], res.c_str());
	}
	else if (command == 'd')
	{
		MEMORYSTATUSEX state;
		state.dwLength = sizeof(state);
		GlobalMemoryStatusEx(&state);

		std::string res("Memory load: " + std::to_string(state.dwMemoryLoad) + " %\n"
			+ "Total physical memory: " + std::to_string((double)state.ullTotalPhys / 1024.0 / 1024.0) + " MB\n"
			+ "Available physical memory: " + std::to_string((double)state.ullAvailPhys / 1024.0 / 1024.0) + " MB\n"
			+ "Total page memory: " + std::to_string((double)state.ullTotalPageFile / 1024.0 / 1024.0) + " MB\n"
			+ "Available page memory: " + std::to_string((double)state.ullAvailPageFile / 1024.0 / 1024.0) + " MB\n"
			+ "Total virtual memory: " + std::to_string((double)state.ullTotalVirtual / 1024.0 / 1024.0) + " MB\n"
			+ "Available virtual memory: " + std::to_string((double)state.ullAvailVirtual / 1024.0 / 1024.0) + " MB");

		strcpy(g_ctxs[idx].buf_send, res.c_str());
	}
	else if (command == 'e')
	{
		DWORD drives = GetLogicalDrives();
		char disks[26][4] = { 0 };
		char file_system[10];
		DWORD sectors, bytes, free_clusters, clusters;
		int disk_count = 0;
		UINT drive_type = 0;
		double free_space = 0.0;
		for (int i = 0; i < 26; i++)
		{
			if ((drives & (1 << i)))
			{
				disks[disk_count][0] = char('A' + i);
				disks[disk_count][1] = ':';
				disks[disk_count][2] = '\\';
				disk_count++;
			}
		}

		std::string res;
		for (int i = 0; i < disk_count; i++)
		{
			res += disks[i];
			res += " ";

			res += "Type: ";
			drive_type = GetDriveTypeA((LPSTR)disks[i]);
			if (drive_type == DRIVE_UNKNOWN) res += "Unknown";
			else if (drive_type == DRIVE_NO_ROOT_DIR) res += "Invalid Root Path";
			else if (drive_type == DRIVE_REMOVABLE) res += "Removable";
			else if (drive_type == DRIVE_FIXED) res += "HDD";
			else if (drive_type == DRIVE_REMOTE) res += "Remote";
			else if (drive_type == DRIVE_CDROM) res += "CD";
			else if (drive_type == DRIVE_RAMDISK) res += "RAM";
			res += " ";

			GetVolumeInformationA((LPSTR)disks[i], NULL, NULL, NULL, NULL, NULL, file_system, 10);
			res += "File system: ";
			res += (const char*)file_system;
			res += " ";

			GetDiskFreeSpaceA((LPSTR)disks[i], &sectors, &bytes, &free_clusters, &clusters);
			res += "Free space: ";
			free_space = (double)free_clusters * (double)sectors * (double)bytes / 1024.0 / 1024.0 / 1024.0;
			res += std::to_string(free_space);
			res += " GB";
			if (i < disk_count - 1) res += '\n';
		}
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], res.c_str());
	}
	else if (command == 'f')
	{
		PACL dacl;
		PSID sidowner = NULL, sidgroup = NULL;
		PSECURITY_DESCRIPTOR sec;
		DWORD owner_name_len = UNLEN, domain_name_len = UNLEN;
		LPSTR owner_name = (LPSTR)LocalAlloc(GMEM_FIXED, owner_name_len);
		LPSTR domain_name = (LPSTR)LocalAlloc(GMEM_FIXED, domain_name_len);
		SID_NAME_USE peUse;
		LPVOID ace;

		GetNamedSecurityInfoA((LPCSTR)arg.c_str(), SE_FILE_OBJECT,
			OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			&sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			GetNamedSecurityInfoA((LPCSTR)arg.c_str(), SE_REGISTRY_KEY,
				OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
				&sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			return;

		LookupAccountSidA(NULL, sidowner, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
		SID* sid = NULL;
		unsigned long mask;
		std::vector<acl> access_control_list;
		for (int i = 0; i < (*dacl).AceCount; i++)
		{
			acl access_control;
			GetAce(dacl, i, &ace);
			ACCESS_ALLOWED_ACE* ace_2 = (ACCESS_ALLOWED_ACE*)ace;
			owner_name_len = UNLEN;
			domain_name_len = UNLEN;
			if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceFlags)
				access_control.inherit = true;
			else
				access_control.inherit = false;
			if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
			{
				access_control.deny_ace = false;
				sid = (SID*)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
				LookupAccountSidA(NULL, sid, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
				access_control.name = std::string(owner_name);
				mask = ((ACCESS_ALLOWED_ACE*)ace)->Mask;
			}
			else if (((ACCESS_DENIED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
			{
				access_control.deny_ace = true;
				sid = (SID*)&((ACCESS_DENIED_ACE*)ace)->SidStart;
				LookupAccountSidA(NULL, sid, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
				access_control.name = std::string(owner_name);
				mask = ((ACCESS_DENIED_ACE*)ace)->Mask;
			}

			if (GENERIC_READ & ace_2->Mask) access_control.ace.push_back(std::string("GENERIC_READ"));
			if (GENERIC_WRITE & ace_2->Mask) access_control.ace.push_back(std::string("GENERIC_WRITE"));
			if (GENERIC_EXECUTE & ace_2->Mask) access_control.ace.push_back(std::string("GENERIC_EXECUTE"));
			if (FILE_GENERIC_READ & ace_2->Mask) access_control.ace.push_back(std::string("FILE_GENERIC_READ"));
			if (FILE_GENERIC_WRITE & ace_2->Mask) access_control.ace.push_back(std::string("FILE_GENERIC_WRITE"));
			if (FILE_GENERIC_EXECUTE & ace_2->Mask) access_control.ace.push_back(std::string("FILE_GENERIC_EXECUTE"));
			if (GENERIC_ALL & ace_2->Mask) access_control.ace.push_back(std::string("GENERIC_ALL"));
			if (DELETE & ace_2->Mask) access_control.ace.push_back(std::string("DELETE"));
			if (READ_CONTROL & ace_2->Mask) access_control.ace.push_back(std::string("READ_CONTROL"));
			if (WRITE_DAC & ace_2->Mask) access_control.ace.push_back(std::string("WRITE_DAC"));
			if (WRITE_OWNER & ace_2->Mask) access_control.ace.push_back(std::string("WRITE_OWNER"));
			if (SYNCHRONIZE & ace_2->Mask) access_control.ace.push_back(std::string("SYNCHRONIZE"));

			access_control_list.push_back(access_control);
			access_control_list[i].mask = ace_2->Mask;
			ConvertSidToStringSidA(sid, &(access_control_list[i].sid));
		}

		std::string s;
		for (int i = 0; i < access_control_list.size(); i++)
		{
			acl access_control = access_control_list[i];

			if (!access_control.deny_ace)
				s += "Access Allowed ACE:\n";
			else
				s += "Access Denied ACE:\n";

			s += access_control.name;
			s += " ";
			s += access_control.sid;
			s += "\n";
			char tmp[100] = { 0 };
			_ltoa(access_control.mask, tmp, 2);
			s += tmp;
			s += "\n";
			for (int j = 0; j < access_control.ace.size(); j++)
			{
				s += access_control.ace[j];
				s += "; ";
			}
			if (i < access_control_list.size() - 1) s += "\n\n";
		}
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], s.c_str());
	}
	else if (command == 'g')
	{
		PACL dacl;
		PSID sidowner = NULL, sidgroup = NULL;
		PSECURITY_DESCRIPTOR sec;
		DWORD owner_name_len = UNLEN, domain_name_len = UNLEN;
		LPSTR owner_name = (LPSTR)LocalAlloc(GMEM_FIXED, owner_name_len);
		LPSTR domain_name = (LPSTR)LocalAlloc(GMEM_FIXED, domain_name_len);
		SID_NAME_USE peUse;

		GetNamedSecurityInfoA((LPCSTR)arg.c_str(), SE_FILE_OBJECT,
			OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, 
			&sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			GetNamedSecurityInfoA((LPCSTR)arg.c_str(), SE_REGISTRY_KEY,
				OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, 
				&sidowner, &sidgroup, &dacl, NULL, &sec);
		if (!dacl)
			return;

		LookupAccountSidA(NULL, sidowner, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
		std::string s(owner_name);
		s += " ";
		char* tmp;
		ConvertSidToStringSidA(sidowner, &tmp);
		s += tmp;
		sprintf(&g_ctxs[idx].buf_send[strlen(g_ctxs[idx].buf_send)], s.c_str());
	}
	else if (command == 'h')
	{
		g_ctxs[idx].CSP_desc = g_ctxs[idx].pb_key_desc = g_ctxs[idx].sess_key_desc = 0;
		memset(g_ctxs[idx].buf_send, 0, 2048);
		CancelIo((HANDLE)g_ctxs[idx].socket);
		PostQueuedCompletionStatus(g_io_port, 0, idx, &g_ctxs[idx].overlap_cancel);
		return;
	}

	std::cout << "Received from client " << idx << ":" << std::endl;
	std::cout << g_ctxs[idx].buf_recv << std::endl;
	std::cout << "Sended to client " << idx << ":" << std::endl;
	std::cout << g_ctxs[idx].buf_send << std::endl;

	data_size = (DWORD)strlen(g_ctxs[idx].buf_send);
	if (!CryptEncrypt(g_ctxs[idx].sess_key_desc, NULL, TRUE, NULL, (BYTE*)g_ctxs[idx].buf_send, (DWORD*)&data_size, 2048))
		std::cout << "Encryption error! Error code: " << GetLastError() << std::endl;
	g_ctxs[idx].sz_send_total = data_size;
}

int main()
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
	{
		std::cout << "Winsock init failed!" << std::endl;
		WSACleanup();
		return 1;
	}

	SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	struct sockaddr_in addr;

	if ((g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0)) == NULL)
	{
		std::cout << "CreateIoCompletionPort error: " << GetLastError() << std::endl;
		return 1;
	}

	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(LISTEN_PORT);
	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(sock, 1) < 0)
	{
		std::cout << "Error in winsock bind() or listen() function!" << std::endl;
		return 1;
	}
	std::cout << "Server listening on port " << ntohs(addr.sin_port) << std::endl;

	if (CreateIoCompletionPort((HANDLE)sock, g_io_port, 0, 0) == NULL)
	{
		std::cout << "CreateIoCompletionPort error: " << GetLastError() << std::endl;
		return 1;
	}
	g_ctxs[0].socket = sock;

	schedule_accept();
	
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		
		if (GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000))
		{
			if (key == 0)
			{
				g_ctxs[0].sz_recv += transferred;

				add_accepted_conn();
				schedule_accept();
			}
			else
			{
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					if (transferred == 0)
					{
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_recv(key, len))
					{
						serve_client(key);
						g_ctxs[key].time = clock();
						g_ctxs[key].sz_send = 0;
						memset(g_ctxs[key].buf_recv, 0, 512);
						schedule_write(key);
					}
					else
						schedule_read(key);
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
						schedule_write(key);
					else
					{
						g_ctxs[key].sz_recv = 0;
						memset(g_ctxs[key].buf_send, 0, 2048);
						schedule_read(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					std::cout << "Connection with client " << key << " is closed" << std::endl;
				}
			}
		}
		else
		{
			for (int k = 1; k < MAX_CLIENTS; k++)
			{
				if (g_ctxs[k].socket != 0 && (clock() - g_ctxs[k].time) / CLOCKS_PER_SEC > CLIENT_TIME)
				{
					CancelIo((HANDLE)g_ctxs[k].socket);
					PostQueuedCompletionStatus(g_io_port, 0, k, &g_ctxs[k].overlap_cancel);
				}
			}
		}
	}

	WSACleanup();
	return 0;
}