#include "Md5Mgr.h"

using namespace std;

DWORD Md5Mgr::CreateMd5(string& file_path_str, string& out)
{
    DWORD dw_status = 0;
    BOOL result = FALSE;
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    HANDLE file = NULL;
    BYTE rgb_file[BUFSIZE];
    DWORD cb_read = 0;
    BYTE rgb_hash[MD5LEN];
    DWORD cb_hash = 0;
    CHAR rgb_digits[] = "0123456789abcdef";
    CString file_path_cstr(file_path_str.c_str());
    BOOL local_ret;

    CHAR md5_temp[33];

    Raii raii_create_file(
        [&]() {
            file = CreateFile((LPCWSTR)file_path_cstr, //file_path_wstr.c_str()
                GENERIC_READ,
                FILE_SHARE_READ,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_SEQUENTIAL_SCAN,
                NULL);

        },
        [&]() {
            CloseHandle(file);
        }
    );
    if (INVALID_HANDLE_VALUE == file)
    {
        dw_status = GetLastError();
        cout << "Error opening file : " << file_path_str << endl
            << "Error : " << dw_status << endl;
        return dw_status;
    }

    // Get handle to the crypto provider
    Raii raii_crypt_acquire_context(
        [&]() {
            local_ret = CryptAcquireContext(&prov,
                NULL,
                NULL,
                PROV_RSA_FULL,
                CRYPT_VERIFYCONTEXT);
        },
        [&]() {
            CryptReleaseContext(prov, 0);
        }
    );
    if (!local_ret)
    {
        dw_status = GetLastError();
        cout << "CryptAcquireContext failed: " << dw_status << endl;
        return dw_status;
    }

    Raii raii_crypt_create_hash(
        [&]() {
            CryptCreateHash(prov, CALG_MD5, 0, 0, &hash);
        },
        [&]() {
            CryptDestroyHash(hash);
        }
    );
    
    if (!local_ret)
    {
        dw_status = GetLastError();
        cout << "CryptAcquireContext failed: " << dw_status << endl;
        return dw_status;
    }

    while (result = ReadFile(file, rgb_file, BUFSIZE,
        &cb_read, NULL))
    {
        if (0 == cb_read)
        {
            break;
        }

        if (!CryptHashData(hash, rgb_file, cb_read, 0))
        {
            dw_status = GetLastError();
            cout << "CryptHashData failed: " << dw_status << endl;
            return dw_status;
        }
    }

    if (!result)
    {
        dw_status = GetLastError();
        cout << "ReadFile failed : % " << dw_status << endl;
        return dw_status;
    }

    cb_hash = MD5LEN;
    if (!CryptGetHashParam(hash, HP_HASHVAL, rgb_hash, &cb_hash, 0))
    {
        dw_status = GetLastError();
        cout << "CryptGetHashParam failed: " << dw_status << endl;
    }

    for (DWORD i = 0; i < cb_hash; i++)
    {
        sprintf_s(md5_temp + 2 * i, sizeof(md5_temp) - 2 * i, "%c%c",
            rgb_digits[rgb_hash[i] >> 4], rgb_digits[rgb_hash[i] & 0xf]);
    }
    out = md5_temp;

    return dw_status;
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