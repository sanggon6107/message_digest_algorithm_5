#include "Md5Mgr.h"

using namespace std;

DWORD Md5Mgr::CreateMd5(string& file_path_str, string& out)
{
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
    CString file_path_cstr(file_path_str.c_str());
    BOOL local_ret;

    CHAR md5_temp[33];

    Raii raii_create_file(
        [&]() {
            hFile = CreateFile((LPCWSTR)file_path_cstr, //file_path_wstr.c_str()
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN,
                NULL);

        },
        [&]() {
            CloseHandle(hFile);
        }
    );
    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwStatus = GetLastError();
        cout << "Error opening file : " << file_path_str << endl
            << "Error : " << dwStatus << endl;
        return dwStatus;
    }

    // Get handle to the crypto provider
    Raii raii_crypt_acquire_context(
        [&]() {
            local_ret = CryptAcquireContext(&hProv,
                NULL,
                NULL,
                PROV_RSA_FULL,
                CRYPT_VERIFYCONTEXT);
        },
        [&]() {
            CryptReleaseContext(hProv, 0);
        }
    );
    if (!local_ret)
    {
        dwStatus = GetLastError();
        cout << "CryptAcquireContext failed: " << dwStatus << endl;
        return dwStatus;
    }

    Raii raii_crypt_create_hash(
        [&]() {
            CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
        },
        [&]() {
            CryptDestroyHash(hHash);
        }
    );
    
    if (!local_ret)
    {
        dwStatus = GetLastError();
        cout << "CryptAcquireContext failed: " << dwStatus << endl;
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
            return dwStatus;
        }
    }

    if (!bResult)
    {
        dwStatus = GetLastError();
        cout << "ReadFile failed : % " << dwStatus << endl;
        return dwStatus;
    }

    cbHash = MD5LEN;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        dwStatus = GetLastError();
        cout << "CryptGetHashParam failed: " << dwStatus << endl;
    }

    for (DWORD i = 0; i < cbHash; i++)
    {
        sprintf_s(md5_temp + 2 * i, sizeof(md5_temp) - 2 * i, "%c%c",
            rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
    }
    out = md5_temp;

    return dwStatus;
}

int Md5Mgr::CheckMd5(string& md5_file_path, string& file_path)
{
    string md5_live{};
    ifstream md5_file;
    string md5_file_hash;
    
    // Get Live Md5 hash from a file.
    DWORD ret = CreateMd5(file_path , md5_live);
    if (ret)
    {
        cout << "Failed to Create MD5" << endl;
        return 2; // 2 : Fail to Create MD5
    }
    
    // Get md5 hash from a *.md5 file.
    md5_file.open(md5_file_path);
    if (!getline(md5_file, md5_file_hash))
    {
        cout << "Failed to get MD5 hash from a *.md5 file" << endl;
        return 3; // 3 : Fail to Get hash from a *.md5 file
    }

    md5_file.close();

    return (md5_file_hash == md5_live)? static_cast<int>(Result::kSuccess) : static_cast<int>(Result::kFail);
}