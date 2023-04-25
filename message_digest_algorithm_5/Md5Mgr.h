#pragma once
#include <windows.h>
#include <Wincrypt.h>
#include <iostream>
#include <string>
#include <fstream>
#include <functional>
#include <atlstr.h>

using namespace std;

#define BUFSIZE 1024
#define MD5LEN  16

enum class Result : int {kSuccess = 0, kFail = 1};


class Md5Mgr
{
public:
    int CheckMd5(string& md5_file_path, string& file_path);
    static Md5Mgr& GetInstance()
    {
        static Md5Mgr instance;
        return instance;
    }

private :
    Md5Mgr() {};

    Md5Mgr(const Md5Mgr& md5_mgr) = delete;
    void operator=(const Md5Mgr&) = delete;
    DWORD CreateMd5(string& file_path_str, string& out);

};

class Raii
{
    using func = function<void(void)>;
public:
    Raii(func init, func dest) : dest_(dest)
    {
        init();
    }

    ~Raii()
    {
        dest_();
    }
    func dest_;
};