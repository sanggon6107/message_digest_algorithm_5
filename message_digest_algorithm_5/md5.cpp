#include <windows.h>
#include <Wincrypt.h>
#include <iostream>
#include <string>
#include <atlstr.h>

using namespace std;

#define BUFSIZE 1024
#define MD5LEN  16

DWORD MessageDigestAlgorithm5(LPCWSTR file_path, string& out)
{
    USES_CONVERSION;

    DWORD dwStatus = 0;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";

    CHAR md5_temp[33];
    
    // Logic to check usage goes here.

    hFile = CreateFile(file_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);


    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        cout << "Error opening file : " << CW2A(file_path) << endl
            << "Error : " << dwStatus << endl;
        return dwStatus;
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwStatus = GetLastError();
        cout << "CryptAcquireContext failed: " << dwStatus << endl;
        CloseHandle(hFile);
        return dwStatus;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        dwStatus = GetLastError();
        cout << "CryptAcquireContext failed: " << dwStatus << endl;
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return dwStatus;
    }

    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
        &cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            dwStatus = GetLastError();
            
            cout << "CryptHashData failed: " << dwStatus << endl;
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return dwStatus;
        }
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        cout << "ReadFile failed : % " << dwStatus << endl;
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return dwStatus;
    }

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {   
        
        for (DWORD i = 0; i < cbHash; i++)
        {
            sprintf_s(md5_temp + 2 * i, sizeof(md5_temp) - 2 * i, "%c%c",
            rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
        }
        out = md5_temp;
    }
    else
    {
        dwStatus = GetLastError();
        cout << "CryptGetHashParam failed: " << dwStatus << endl;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return dwStatus;
}

int main()
{
    string out;
    DWORD ret = MessageDigestAlgorithm5(L"example.txt", out);
    if (!ret)
    {
        cout << out << endl;
    }
    
    return 0;
}