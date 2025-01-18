#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 4096
#define KEY_BUF_SIZE 256
#define MAX_RETRY 5

struct my_secure_socket
{
	SOCKET sock;
	HCRYPTPROV CSP_desc;
	HCRYPTKEY key_pair_desc, public_key_desc, private_key_desc;
	HCRYPTKEY sess_key_desc;
};

std::vector<my_secure_socket> secure_sockets_arr;

int try_connect(SOCKET sock, struct sockaddr_in addr)
{
	for (int i = 0; i < MAX_RETRY; i++)
	{
		if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0)
			return 0;
		else
		{
			std::cout << "Retrying connect to server..." << std::endl;
			Sleep(200);
		}
	}
	return 1;
}

int socket_err(const char* msg)
{
	std::cout << "Error in winsock: " << msg << ". Error code: " << WSAGetLastError() << std::endl;
	return 1;
}

int str_rlen(char* str, int buf_size)
{
	int i = buf_size - 1;
	for (; i >= 0; i--)
		if (str[i] != '\0') break;
	return i + 1;
}

void crypt_init(SOCKET& sock)
{
	my_secure_socket result;

	if (!CryptAcquireContextW(&result.CSP_desc, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
	{
		if (!CryptAcquireContextW(&result.CSP_desc, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			std::cout << "Error acquiring handle to key container!" << std::endl;
	}

	if (!CryptGenKey(result.CSP_desc, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &result.key_pair_desc))
		std::cout << "Error generating public/private key pair!" << std::endl;
	if (!CryptGetUserKey(result.CSP_desc, AT_KEYEXCHANGE, &result.public_key_desc))
		std::cout << "Error retrieving public key!" << std::endl;
	if (!CryptGetUserKey(result.CSP_desc, AT_KEYEXCHANGE, &result.private_key_desc))
		std::cout << "Error retrieving private key!" << std::endl;

	char exp_buf[KEY_BUF_SIZE] = { 0 };
	DWORD len = KEY_BUF_SIZE;

	if (!CryptExportKey(result.public_key_desc, 0, PUBLICKEYBLOB, NULL, (BYTE*)exp_buf, &len))
		std::cout << "Error exporting public key!" << std::endl;

	int exp_buf_size = str_rlen(exp_buf, KEY_BUF_SIZE);
	exp_buf[exp_buf_size] = exp_buf_size;

	if (send(sock, exp_buf, exp_buf_size + 1, 0) < 0)
		socket_err("send()");

	char imp_buf[KEY_BUF_SIZE] = { 0 };
	if (recv(sock, imp_buf, KEY_BUF_SIZE, 0) < 0)
		socket_err("recv()");

	int imp_buf_size = str_rlen(imp_buf, KEY_BUF_SIZE);
	unsigned int data_len = (unsigned char)imp_buf[imp_buf_size - 1];
	imp_buf[imp_buf_size - 1] = 0;

	if (!CryptImportKey(result.CSP_desc, (BYTE*)imp_buf, data_len, result.private_key_desc, 0, &result.sess_key_desc))
		std::cout << "Error importing session key!" << std::endl;

	result.sock = sock;
	secure_sockets_arr.push_back(result);
}

void mod_command(char* user_input, char* mod_command)
{
	char command[BUFFER_SIZE] = { 0 };
	int args_start = -1;

	int i = 0;
	for (; i < strlen(user_input); i++)
	{
		if (user_input[i] == ' ')
		{
			args_start = i + 1;
			break;
		}

		command[i] = user_input[i];
	}
	command[i] = '\0';

	if (!strcmp(command, "version"))
	{
		mod_command[0] = 'a';
		mod_command[1] = '\0';
		return;
	}
	else if (!strcmp(command, "time"))
	{
		mod_command[0] = 'b';
		mod_command[1] = '\0';
		return;
	}
	else if (!strcmp(command, "boot_time"))
	{
		mod_command[0] = 'c';
		mod_command[1] = '\0';
		return;
	}
	else if (!strcmp(command, "mem_usage"))
	{
		mod_command[0] = 'd';
		mod_command[1] = '\0';
		return;
	}
	else if (!strcmp(command, "disks"))
	{
		mod_command[0] = 'e';
		mod_command[1] = '\0';
		return;
	}
	else if (!strcmp(command, "get_perms"))
	{
		mod_command[0] = 'f';
		mod_command[1] = ' ';
	}
	else if (!strcmp(command, "get_owner"))
	{
		mod_command[0] = 'g';
		mod_command[1] = ' ';
	}
	else if (!strcmp(command, "remove_pc"))
	{
		mod_command[0] = 'h';
		mod_command[1] = '\0';
		return;
	}

	int j = 0;
	for (i = 2, j = args_start; j < strlen(user_input); i++, j++)
		mod_command[i] = user_input[j];
	mod_command[i] = '\0';
}

int query(int socket_num, char* input_buf, unsigned int input_size, char* output_buf, unsigned int& output_size)
{
	if (!CryptEncrypt(secure_sockets_arr[socket_num].sess_key_desc, 0, TRUE, 0, (BYTE*)input_buf, (DWORD*)&input_size, BUFFER_SIZE))
	{
		std::cout << "Encryption error! Error code: " << GetLastError() << std::endl;
		return 1;
	}

	if (send(secure_sockets_arr[socket_num].sock, input_buf, input_size, 0) < 0)
	{
		socket_err("send()");
		return 1;
	}
	if (recv(secure_sockets_arr[socket_num].sock, output_buf, BUFFER_SIZE, 0) < 0)
	{
		socket_err("recv()");
		return 1;
	}

	output_size = str_rlen(output_buf, BUFFER_SIZE);
	if (!CryptDecrypt(secure_sockets_arr[socket_num].sess_key_desc, NULL, TRUE, NULL, (BYTE*)output_buf, (DWORD*)&output_size))
	{
		std::cout << "Decryption error! Error code: " << GetLastError() << std::endl;
		return 1;
	}

	return 0;
}

int close_conn(int socket_num, char* input_buf, unsigned int input_size)
{
	if (!CryptEncrypt(secure_sockets_arr[socket_num].sess_key_desc, 0, TRUE, 0, (BYTE*)input_buf, (DWORD*)&input_size, BUFFER_SIZE))
	{
		std::cout << "Encryption error! Error code: " << GetLastError() << std::endl;
		return 0;
	}

	if (send(secure_sockets_arr[socket_num].sock, input_buf, input_size, 0) < 0)
	{
		socket_err("send()");
		return 0;
	}

	closesocket(socket_num);
	std::cout << std::endl << "Connection closed!" << std::endl << std::endl;

	return 1;
}

void show_help()
{
	std::cout << std::endl;
	std::cout << "Available commands:" << std::endl;
	std::cout << " version          - show OS version" << std::endl;
	std::cout << " time             - show current time" << std::endl;
	std::cout << " boot_time        - show time since boot" << std::endl;
	std::cout << " mem_usage        - show memory usage stats" << std::endl;
	std::cout << " disks            - show disk info and usage stats" << std::endl;
	std::cout << " get_perms <path> - get permissions of the specified object" << std::endl;
	std::cout << " get_owner <path> - get owner ot the specified object" << std::endl;
	std::cout << " remove_pc        - close connection to server" << std::endl << std::endl;
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

	char command[BUFFER_SIZE];
	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];

	int PC_num = 0;
	unsigned int send_size = 0;
	unsigned int recv_size = 0;

	while (1)
	{
		memset(command, 0, BUFFER_SIZE);

		std::cout << "Choose an action:" << std::endl;
		std::cout << "1) And new PC" << std::endl;
		std::cout << "2) Query existing PC" << std::endl;
		std::cout << "3) Show commands list" << std::endl;
		std::cout << "> ";
		std::cin >> command;

		if (!strcmp(command, "1"))
		{
			std::string ip;
			short port;
			std::cout << "IP address: ";
			std::cin >> ip;
			std::cout << "Port number: ";
			std::cin >> port;

			SOCKET sock;
			struct sockaddr_in addr;

			sock = socket(AF_INET, SOCK_STREAM, 0);
			if (sock < 0)
			{
				WSACleanup();
				return socket_err("socket()");
			}

			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;
			addr.sin_port = htons(port);
			addr.sin_addr.s_addr = inet_addr(ip.c_str());

			if (try_connect(sock, addr) != 0)
			{
				closesocket(sock);
				return socket_err("connect()");
			}

			std::cout << std::endl << "Connected to the server!" << std::endl;

			crypt_init(sock);
			std::cout << "Secure connection established!" << std::endl;

			int new_pc_num = (int)secure_sockets_arr.size();
			std::cout << "New PC number: " << new_pc_num << std::endl << std::endl;
		}
		else if (!strcmp(command, "2"))
		{
			memset(command, 0, BUFFER_SIZE);
			memset(send_buffer, 0, BUFFER_SIZE);
			memset(recv_buffer, 0, BUFFER_SIZE);

			std::cout << "Enter PC number: ";
			std::cin >> PC_num;
			std::cout << "Enter command: ";
			std::string command_input;
			std::getline(std::cin >> std::ws, command_input);

			strcpy(command, command_input.c_str());

			mod_command(command, send_buffer);

			send_size = (int)strlen(send_buffer);

			if (send_buffer[0] >= 'a' && send_buffer[0] <= 'g')
			{
				if (query(PC_num - 1, send_buffer, send_size, recv_buffer, recv_size) != -1)
					std::cout << std::endl << recv_buffer << std::endl << std::endl;
				else
					std::cout << "An error occured!" << std::endl;
			}
			else if (send_buffer[0] == 'h')
			{
				if (!close_conn(PC_num - 1, send_buffer, send_size))
					std::cout << "An error occured!" << std::endl;
			}
			else
			{
				std::cout << "Incorrect input!" << std::endl;
			}
		}
		else if (!strcmp(command, "3"))
			show_help();
		else
			std::cout << "Incorrect choice!" << std::endl;
	}

	WSACleanup();
	return 0;
}