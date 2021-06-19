#include "RC6.h"
RC6_class::RC6_class(const string& fin, const string& fout, const string& pass)
{
    this->fin=fin;
    this->fout=fout;
    this->pass=pass;
}

RC6_class::RC6_class(const string& fin, const string& fout, const string& pass, const string& IV)
{
    this->fin=fin;
    this->fout=fout;
    this->pass=pass;
    this->IV=IV;
}

void RC6_class::encryptRC6(RC6_class encr)
{
    // Генерация ключа из пароля
    SecByteBlock key(RC6::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)encr.pass.data(), encr.pass.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);
    
    // Генерация вектора инициализации
    byte iv[RC6::BLOCKSIZE];
    ofstream write_iv(string(encr.fout+".iv").c_str(), ios::binary | ios::out);
    write_iv.write((char*)iv, RC6::BLOCKSIZE);
    write_iv.close();
    cout<<"Был создан файл с вектором инициализации, находится в файле по следующему пути -> "<<encr.fout+".iv"<<endl;
    CBC_Mode<RC6>::Encryption enc;
    enc.SetKeyWithIV(key, key.size(), iv);
    FileSource s(encr.fin.c_str(), true, new StreamTransformationFilter(enc, new FileSink(encr.fout.c_str())));
    cout <<"Зашифрованное сообщение было успешно записано в файл. Результат находится в файле по следующему пути -> "<<encr.fout << endl;
}
void RC6_class::decryptRC6(RC6_class decr)
{
    SecByteBlock key (RC6::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)decr.pass.data(), pass.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Вектор инициализации из файла, который формируется при шифровании
    byte iv[RC6::BLOCKSIZE];
    ifstream write_iv(decr.IV.c_str(), ios::in | ios::binary);
    //Проверки файла с вектором инициализации на ошибки
    if (!write_iv.good()) {
        cerr<<"Ошибка открытия файла с вектором инициализации"<<endl;
    }
    write_iv.read((char*)(&iv), RC6::BLOCKSIZE);
      

    //Расшифрование
    CBC_Mode<RC6>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), iv);
    FileSource s(decr.fin.c_str(), true, new StreamTransformationFilter(dec, new FileSink(decr.fout.c_str())));
    cout << "Расшифрованное сообщение было успешно записано в файл. Результат находится в файле по следующему пути -> " << decr.fout << endl;
    
}