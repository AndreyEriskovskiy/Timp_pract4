#include "AES.h"
#include "RC6.h"
using namespace std;

int main()
{
    string password, file_in, file_out, file_iv, mode;
    string exit="exit";
    cout<<"Добро пожаловать в программу для зашифрования и расшифрования файлов"<<endl;
    cout<<"Режимы работы программы: "<<endl;
    cout<<"encryptAES - зашифрование по алгоритму \"AES\""<<endl;
    cout<<"decryptAES - расшифрование по алгоритму \"AES\""<<endl;
    cout<<"encryptRC6 - зашифрование по алгоритму \"RC6\""<<endl;
    cout<<"decryptRC6 - расшифрование пл алгоритму \"RC6\""<<endl;
    cout<<"exit - завершение программы"<<endl;
    do {
        cout<<"Выберите режим работы: ";
        cin>>mode;
        if(mode=="encryptAES") {
            cout<<"Введите путь до файла: ";
            cin>>file_in;
            cout<<"Введите путь до файла, где будет храниться результат: ";
            cin>>file_out;
            cout<<"Введите пароль: ";
            cin>>password;
            try {
                Aes_class encr(file_in,file_out,password);
                encr.encryptAES(encr);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "decryptAES") {
            cout<<"Введите путь до файла: ";
            cin>>file_in;
            cout<<"Введите путь до файла, где будет храниться результат: ";
            cin>>file_out;
            cout<<"Введите путь до файла, в котором храниться вектор инициализации: ";
            cin>>file_iv;
            cout<<"Введите пароль: ";
            cin>>password;
            try {
                Aes_class decr(file_in,file_out,password,file_iv);
                decr.decryptAES(decr);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "encryptRC6") {
            cout << "Введите путь до файла: ";
            cin>>file_in;
            cout<<"Введите путь до файла, где будет храниться результат: ";
            cin>>file_out;
            cout<<"Введите пароль: ";
            cin>>password;
            try {
                RC6_class encr(file_in,file_out,password);
                encr.encryptRC6(encr);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if(mode=="decryptRC6") {
            cout << "Введите путь до файла: ";
            cin>>file_in;
            cout<<"Введите путь до файла, где будет храниться результат: ";
            cin>>file_out;
            cout<<"Введите путь до файла, содержащий вектор инициализации: ";
            cin>>file_iv;
            cout<<"Введите пароль: ";
            cin>>password;
            try {
                RC6_class decr(file_in,file_out,password,file_iv);
                decr.decryptRC6(decr);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }

        }

        if (mode == exit) {
            cout << "Завершение работы..." << endl;
            return 0;
        }

    } while(mode!=exit);

}
