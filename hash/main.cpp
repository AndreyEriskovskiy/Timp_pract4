#include <iostream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <fstream>
using namespace std;
using namespace CryptoPP;
int main()
{
    SHA256 sha; // хэш-объект
    cout<<"Name: "<<sha.AlgorithmName()<<endl; // имя хэш-функции
    cout<<"Digest size: "<<sha.DigestSize()<<endl; // размер хэша
    cout<<"Block size: "<<sha.BlockSize()<<endl; // размер блока для вычислений
    string filename;
    cout<<"Введите имя файла: ";
    getline(cin, filename);
    ifstream fin(filename);
    if(!fin.good()) {
        cerr<<"Ошибка открытия файла"<<endl;
        exit(1);
    }
    string digest;
    string hash1;
    while(getline(fin,hash1)) {
        StringSource (hash1, true, new HashFilter(sha, new HexEncoder(new StringSink(digest)))); // цепочка фильтров
        cout<<"Hash: "<<digest<<endl;

    }
    return 0;
}
