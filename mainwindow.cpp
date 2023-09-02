#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <QFileDialog>
#include <fstream>

#include <iostream>
#include <fstream>
#include <bitset>
#include <random>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    socket = new QTcpSocket(this);
    connect(socket, &QTcpSocket::readyRead, this, &MainWindow::slotReadyRead);
    connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    nextBlockSize = 0;
}

MainWindow::~MainWindow()
{
    delete ui;
}

std::vector<unsigned long long> keygen(const std::string &keyStr, int countDesKeys) {
    unsigned long long desKey;
    std::string desKeyStr;
    std::vector<unsigned long long> desKeys, roundKeys;
    for (int i = 0; i < countDesKeys; i++) {
        desKey = 0;
        desKeyStr = keyStr.substr(i*7, 7);
        for (int j = 0; j < 7; j++) {
            desKey += keyStr[j];
            desKey <<= 8;
        }
        desKey = (desKey & 0xFF00000000000000) | ((desKey & 0x01FFFFFFFFFFFFFF) >> 1);
        desKey = (desKey & 0xFFFF000000000000) | ((desKey & 0x0001FFFFFFFFFFFF) >> 1);
        desKey = (desKey & 0xFFFFFF0000000000) | ((desKey & 0x000001FFFFFFFFFF) >> 1);
        desKey = (desKey & 0xFFFFFFFF00000000) | ((desKey & 0x0000001FFFFFFFFF) >> 1);
        desKey = (desKey & 0xFFFFFFFFFF000000) | ((desKey & 0x000000001FFFFFFF) >> 1);
        desKey = (desKey & 0xFFFFFFFFFFFF0000) | ((desKey & 0x00000000001FFFFF) >> 1);
        desKey = (desKey & 0xFFFFFFFFFFFFFF00) | ((desKey & 0x00000000000001FF) >> 1);

        std::bitset<64> desKeyBits(desKey);
        bool controlBit = 1;
        for (int j = 0; j < 64; j++) {
            if (j == 8 || j == 16 || j == 24 || j == 32 || j == 40 || j == 48 || j == 56) continue;
            else if (desKeyBits[j] == 1) controlBit ^= 1;

            if (j == 7 || j == 15 || j == 23 || j == 31 || j == 39 || j == 47 || j == 55 || j == 63) {
                if (controlBit == 1) desKeyBits.set((j / 8) * 8);
                else {
                    desKeyBits.reset((j / 8) * 8);
                    controlBit = 1;
                }
            }
        }
        desKeys.push_back(desKeyBits.to_ullong());
    }

    unsigned long long additionalNum1 = 0x8000000000000000;
    unsigned long long additionalNum2 = 0x6000000000000000;
    unsigned long long additionalNum4 = 0x1000000000000000;
    unsigned long long additionalNum8 = 0x0100000000000000;

    if (countDesKeys == 2) {
        roundKeys.push_back(desKeys[0]);
        roundKeys.push_back(desKeys[1] ^ roundKeys[0]);
        roundKeys.push_back(desKeys[0] ^ additionalNum1 ^ roundKeys[1]);
        roundKeys.push_back(desKeys[1] ^ additionalNum2 ^ roundKeys[2]);
        roundKeys.push_back(desKeys[0] ^ additionalNum4 ^ roundKeys[3]);
        roundKeys.push_back(desKeys[1] ^ additionalNum8 ^ roundKeys[4]);
    }
    else if (countDesKeys == 3) {
        roundKeys.push_back(desKeys[0]);
        roundKeys.push_back(desKeys[1] ^ roundKeys[0]);
        roundKeys.push_back(desKeys[0] ^ additionalNum1 ^ roundKeys[1]);
        roundKeys.push_back(desKeys[1] ^ additionalNum2 ^ roundKeys[2]);
        roundKeys.push_back(desKeys[0] ^ additionalNum4 ^ roundKeys[3]);
        roundKeys.push_back(desKeys[2] ^ additionalNum8 ^ roundKeys[4]);
    }
    else if (countDesKeys == 4) {
        roundKeys.push_back(desKeys[0]);
        roundKeys.push_back(desKeys[1] ^ roundKeys[0]);
        roundKeys.push_back(desKeys[2] ^ roundKeys[1]);
        roundKeys.push_back(desKeys[3] ^ roundKeys[2]);
        roundKeys.push_back(desKeys[0] ^ additionalNum1 ^ roundKeys[3]);
        roundKeys.push_back(desKeys[1] ^ additionalNum2 ^ roundKeys[4]);
        roundKeys.push_back(desKeys[2] ^ additionalNum4 ^ roundKeys[5]);
        roundKeys.push_back(desKeys[3] ^ additionalNum8 ^ roundKeys[6]);

    }
    return roundKeys;
}

void MainWindow::encrypt(const std::string& pathInFile, const std::string& pathOutFile, const std::string &keyStr, const std::string &keyBits, const std::string &mode) {
    ui->progressBar->setValue(0);
    unsigned long long counterLeft = 0, counterRight = 1, counter = 1; // для режима CTR
    unsigned long long leftBits = 0, rightBits = 0;
    std::vector<unsigned long long> roundKeys;
    if (keyBits == "128")
        roundKeys = keygen(keyStr, 2);
    else if (keyBits == "196")
        roundKeys = keygen(keyStr, 3);
    else if (keyBits == "196")
        roundKeys = keygen(keyStr, 4);
    else {
        perror("Error input mode");
        exit(-1);
    }
    char ch;

    //Источник
    std::random_device rd;
    //Генератор
    std::default_random_engine generator(rd());
    // Распределение
    std::uniform_int_distribution<unsigned long long> distribution(0, 0xFFFFFFFFFFFFFFFF);
    unsigned long long initVecLeft = distribution(generator), initVecRight = distribution(generator);
    unsigned long long lastLeftBits = initVecLeft, lastRightBits = initVecRight, xorOut;

    std::ifstream in(pathInFile, std::ios_base::binary);
    std::ofstream out(pathOutFile, std::ios_base::binary);
    if (!in.is_open()) {
        perror("Error input file");
        exit(1);
    }
    if (!out.is_open()) {
        perror("Error output file");
        exit(2);
    }

    for (int j = 0; j < (int)roundKeys.size(); j++) {
        xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
        lastRightBits = lastLeftBits;
        lastLeftBits = xorOut;
    }

    for (int j = 0; j < 8; j++) {
        ch = (char)lastLeftBits;
        out << ch;
        lastLeftBits >>= 8;
    }
    for (int j = 0; j < 8; j++) {
        ch = (char)lastRightBits;
        out << ch;
        lastRightBits >>= 8;
    }

    in.seekg(0, in.end);
    unsigned long long lengthFile = in.tellg();
    in.seekg(0, in.beg);

    lastLeftBits = initVecLeft; lastRightBits = initVecRight;
    unsigned long long diff = 0, count = 0, i = 0;

    while (in.get(ch)) {
        count++; i++;
        ui->progressBar->setValue(i / lengthFile * 100);
        rightBits ^= ((unsigned long long)ch << 56);
        if (count == 8) {
            leftBits = rightBits;
            rightBits = 0;
        }
        else if (count == 16 || i == lengthFile) {

            // набивка PKCS7
            if (i == lengthFile && count != 16) {
                diff = 16 - count;
                //cout << count << endl;
                if (count < 8) {
                    leftBits = rightBits;
                    rightBits = 0;
                    for (int j = 0; j < 8; j++) {
                        rightBits ^= diff;
                        diff <<= 8;
                    }
                    diff = 16 - count;
                    for (int j = 0; j < 8 - count; j++) {
                        leftBits ^= diff;
                        diff <<= 8;
                    }
                }
                else if (count < 16 && count >= 8) {
                    for (int j = 0; j < 16 - count; j++) {
                        rightBits ^= diff;
                        diff <<= 8;
                    }
                }
                //diff = 16 - count;
                //cout << hex << diff << endl;
                //cout << hex << leftBits << " " << rightBits << endl;
            }

            if (mode == "CBC") {
                leftBits ^= lastLeftBits;
                rightBits ^= lastRightBits;
                for (int j = 0; j < (int)roundKeys.size(); j++) {
                    xorOut = leftBits ^ roundKeys[j] ^ rightBits;
                    rightBits = leftBits;
                    leftBits = xorOut;
                }
                lastLeftBits = leftBits; lastRightBits = rightBits;
            }
            else if (mode == "CFB") {
                for (int j = 0; j < (int)roundKeys.size(); j++) {
                    xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
                    lastRightBits = lastLeftBits;
                    lastLeftBits = xorOut;
                }
                leftBits ^= lastLeftBits;
                rightBits ^= lastRightBits;
                lastLeftBits = leftBits; lastRightBits = rightBits;
            }
            else if (mode == "OFB") {
                for (int j = 0; j < (int)roundKeys.size(); j++) {
                    xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
                    lastRightBits = lastLeftBits;
                    lastLeftBits = xorOut;
                }
                leftBits ^= lastLeftBits;
                rightBits ^= lastRightBits;
            }
            else if (mode == "CTR") {
                for (int j = 0; j < (int)roundKeys.size(); j++) {
                    xorOut = counterLeft ^ roundKeys[j] ^ counterRight;
                    counterRight = counterLeft;
                    counterLeft = xorOut;
                }
                leftBits ^= counterLeft;
                rightBits ^= counterRight;
                counter++; counterRight = counter; counterLeft = 0;
            }
            else if (mode == "RD") {
                leftBits ^= lastLeftBits;
                rightBits ^= lastRightBits;
                for (int j = 0; j < (int)roundKeys.size(); j++) {
                    xorOut = leftBits ^ roundKeys[j] ^ rightBits;
                    rightBits = leftBits;
                    leftBits = xorOut;
                }
                lastRightBits += lastRightBits;
            }

            for (int j = 0; j < 8; j++) {
                ch = (char)leftBits;
                out << ch;
                leftBits >>= 8;
            }
            for (int j = 0; j < 8; j++) {
                ch = (char)rightBits;
                out << ch;
                rightBits >>= 8;
            }

            if (i == lengthFile && count == 16) {
                diff = 16;
                for (int j = 0; j < 8; j++) {
                    leftBits ^= diff;
                    rightBits ^= diff;
                    diff <<= 8;
                }
                if (mode == "CBC") {
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = leftBits ^ roundKeys[j] ^ rightBits;
                        rightBits = leftBits;
                        leftBits = xorOut;
                    }
                    lastLeftBits = leftBits; lastRightBits = rightBits;
                }
                else if (mode == "CFB") {
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
                        lastRightBits = lastLeftBits;
                        lastLeftBits = xorOut;
                    }
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                    lastLeftBits = leftBits; lastRightBits = rightBits;
                }
                else if (mode == "OFB") {
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
                        lastRightBits = lastLeftBits;
                        lastLeftBits = xorOut;
                    }
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                }
                else if (mode == "CTR") {
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = counterLeft ^ roundKeys[j] ^ counterRight;
                        counterRight = counterLeft;
                        counterLeft = xorOut;
                    }
                    leftBits ^= counterLeft;
                    rightBits ^= counterRight;
                    counter++; counterRight = counter; counterLeft = 0;
                }
                else if (mode == "RD") {
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = leftBits ^ roundKeys[j] ^ rightBits;
                        rightBits = leftBits;
                        leftBits = xorOut;
                    }
                    lastRightBits += lastRightBits;
                }
                for (int j = 0; j < 8; j++) {
                    ch = (char)leftBits;
                    out << ch;
                    leftBits >>= 8;
                }
                for (int j = 0; j < 8; j++) {
                    ch = (char)rightBits;
                    out << ch;
                    rightBits >>= 8;
                }
            }

            count = 0;
            rightBits = 0;
            leftBits = 0;
        }
        else
            rightBits >>= 8;
    }

    in.close();
    out.close();
}

void MainWindow::decrypt(const std::string &pathInFile, const std::string &pathOutFile, const std::string &keyStr, const std::string &keyBits, const std::string &mode) {
    ui->progressBar->setValue(0);
    unsigned long long counterLeft = 0, counterRight = 1, counter = 1; // для режима CTR
    unsigned long long leftBits = 0, rightBits = 0;
    std::vector<unsigned long long> roundKeys;
    if (keyBits == "128")
        roundKeys = keygen(keyStr, 2);
    else if (keyBits == "196")
        roundKeys = keygen(keyStr, 3);
    else if (keyBits == "196")
        roundKeys = keygen(keyStr, 4);
    else {
        perror("Error input mode");
        exit(-1);
    }
    char ch, diff = 0;


    unsigned long long initVecLeft = 0, initVecRight = 0;
    unsigned long long lastLeftBits, lastRightBits, xorOut;

    std::ifstream in(pathInFile, std::ios_base::binary);
    std::ofstream out(pathOutFile, std::ios_base::binary);
    if (!in.is_open()) {
        perror("Error input file");
        exit(3);
    }
    if (!out.is_open()) {
        perror("Error output file");
        exit(4);
    }

    in.seekg(0, in.end);
    unsigned long long lengthFile = in.tellg();
    in.seekg(0, in.beg);

    for (int j = 0; j < 8; j++) {
        initVecLeft >>= 8;
        in.get(ch);
        initVecLeft ^= ((unsigned long long)ch << 56);
    }
    for (int j = 0; j < 8; j++) {
        initVecRight >>= 8;
        in.get(ch);
        initVecRight ^= ((unsigned long long)ch << 56);
    }
    lastLeftBits = initVecLeft; lastRightBits = initVecRight;
    for (int j = 0; j < (int)roundKeys.size(); j++) {
        xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
        lastRightBits = lastLeftBits;
        lastLeftBits = xorOut;
    }

    unsigned long long bufferLeft, bufferRight;
    unsigned long long count = 0, i = 16;
    ui->progressBar->setValue(i / lengthFile * 100);


    while (in.get(ch)) {
        count++; i++;
        ui->progressBar->setValue(i / lengthFile * 100);
        rightBits ^= ((unsigned long long)ch << 56);
        if (count == 8) {
            leftBits = rightBits;
            rightBits = 0;
        }
        else if (count == 16 || i == lengthFile) {

            bufferLeft = leftBits; bufferRight = rightBits;
            if (count == 16) {
                if (mode == "CBC") {
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = leftBits ^ roundKeys[j] ^ rightBits;
                        rightBits = leftBits;
                        leftBits = xorOut;
                    }
                    lastLeftBits = bufferLeft; lastRightBits = bufferRight;
                }
                else if (mode == "CFB") {
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
                        lastRightBits = lastLeftBits;
                        lastLeftBits = xorOut;
                    }
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                    lastLeftBits = bufferLeft; lastRightBits = bufferRight;
                }
                else if (mode == "OFB") {
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = lastLeftBits ^ roundKeys[j] ^ lastRightBits;
                        lastRightBits = lastLeftBits;
                        lastLeftBits = xorOut;
                    }
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                }
                else if (mode == "CTR") {
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = counterLeft ^ roundKeys[j] ^ counterRight;
                        counterRight = counterLeft;
                        counterLeft = xorOut;
                    }
                    leftBits ^= counterLeft;
                    rightBits ^= counterRight;
                    counter++; counterRight = counter; counterLeft = 0;
                }
                else if (mode == "RD") {
                    leftBits ^= lastLeftBits;
                    rightBits ^= lastRightBits;
                    for (int j = 0; j < (int)roundKeys.size(); j++) {
                        xorOut = leftBits ^ roundKeys[j] ^ rightBits;
                        rightBits = leftBits;
                        leftBits = xorOut;
                    }
                    lastRightBits += lastRightBits;
                }
            }
            // для избавления от набивки PKCS7
            if (i == lengthFile) {
                diff = (char)rightBits;
                //cout << hex << leftBits << " " << rightBits << endl;
                //cout << dec << (int)diff << endl;
                if (diff <= 8 && diff > 0) {
                    leftBits >>= 8 * diff;
                    for (int j = 0; j < 8; j++) {
                        ch = (char)leftBits;
                        out << ch;
                        leftBits >>= 8;
                    }
                    rightBits >>= ((16 - diff) * 8);
                    for (int j = 0; j < 8 - diff; j++) {
                        ch = (char)rightBits;
                        out << ch;
                        rightBits >>= 8;
                    }
                }
                else if (diff < 16 && diff >= 8) {
                    leftBits >>= 8 * diff;
                    for (int j = 0; j < 16 - diff; j++) {
                        ch = (char)leftBits;
                        out << ch;
                        leftBits >>= 8;
                    }
                }
            }
            else {
                for (int j = 0; j < 8; j++) {
                    ch = (char)leftBits;
                    out << ch;
                    leftBits >>= 8;
                }
                for (int j = 0; j < 8; j++) {
                    ch = (char)rightBits;
                    out << ch;
                    rightBits >>= 8;
                }
            }

            count = 0;
            rightBits = 0;
            leftBits = 0;
        }
        else
            rightBits >>= 8;
    }

    in.close();
    out.close();
}

unsigned long long modulo(unsigned long long base, unsigned long long e, unsigned long long mod) {
    unsigned long long a = 1;
    unsigned long long b = base;
    while (e > 0) {
        if (e % 2 == 1)
            a = (a * b) % mod;
        b = (b * b) % mod;
        e = e / 2;
    }
    return a % mod;
}
bool Fermat(unsigned long long m) {
    if (m == 1) {
        return false;
    }
    for (int i = 0; i < 100; i++) {
        unsigned long long x = rand() % (m - 1) + 1;
        if (modulo(x, m - 1, m) != 1) {
            return false;
        }
    }
    return true;
}

unsigned long long gcd(unsigned long long a, unsigned long long b) {
    return b ? gcd(b, a % b) : a;
}

void encryptBenaloh() {
    unsigned long long R = 64;
    unsigned long long p, q, p_minus_one, q_minus_one;
    bool fermaTest;
    //Источник
    std::random_device rd;
    //Генератор
    std::default_random_engine generator(rd());
    // Распределение
    std::uniform_int_distribution<unsigned long long> distribution(0, 0xFFFFFFFFFFFFFFFF);

    do {
        p = distribution(generator);
        p_minus_one = p - 1;
    } while (p_minus_one % R != 0 || gcd(p_minus_one / R, R) != 1);

    do {
        q = distribution(generator);
        q_minus_one = q - 1;
    } while (p == q || gcd(q_minus_one, R) != 1);

    unsigned long long n = p * q, phi = p_minus_one * q_minus_one;

    unsigned long long y;
    do {
        y = distribution(generator);
    } while (y >= n || gcd(y, n) != 1 || (y ^ (phi / R)) % n == 1);
    unsigned long long x = (y ^ (phi / R)) % n;

    unsigned long long m = 15;
    unsigned long long u;
    do {
        u = distribution(generator);
    } while (u >= n || gcd(u, n) != 1);
    unsigned long long cipher1 = (y ^ m) % n;
    unsigned long long cipher2 = (u ^ R) % n;
    unsigned long long c = cipher1 * cipher2 % n;

    unsigned long long a = (c ^ (phi / R)) % n;
    unsigned long long ciph;
    int mes = -2;
    for (int i = 0; i < R; i++) {
        ciph = (x ^ i) % n;
        if (a == ciph) mes = i;
    }
}


void MainWindow::on_pushButton_6_clicked()
{
    socket->connectToHost("127.0.0.1", 2323);
}

void MainWindow::SendToServer(QString str) {
    Data.clear();
    QDataStream out(&Data, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_6);
    out << quint16(0) << str;
    out.device()->seek(0);
    out << quint16(Data.size() - sizeof(quint16));
    socket->write(Data);
}

void MainWindow::slotReadyRead() {
    QDataStream in(socket);
    in.setVersion(QDataStream::Qt_6_6);
    if(in.status()==QDataStream::Ok) {
        /*QString str;
        in >> str;
        //ui->textBrowser->append(str);*/
        for(;;) {
            if (nextBlockSize == 0) {
                if (socket->bytesAvailable() < 2) {
                    break;
                }
                in >> nextBlockSize;
            }
            if (socket->bytesAvailable() < nextBlockSize) {
                break;
            }
            QString str;
            in >> str;
            nextBlockSize = 0;
            //ui->textBrowser->append(str);
        }
    }
    else {
        //ui->textBrowser->append("read error");
    }
}
void MainWindow::on_pushButton_4_clicked()
{
    //SendToServer();
}


void MainWindow::on_pushButton_encrypt_clicked()
{
    QString inFile = ui->textEdit_pathInputFile->toPlainText();
    QString outFile = ui->textEdit_pathOutputFile->toPlainText();
    QString key = ui->plainTextEdit_key->toPlainText();
    QString algorithm = ui->comboBox_algorithm->currentText();
    QString mode = ui->comboBox_mode->currentText();

    outFile += "/encrypted-" + inFile.section("/",-1,-1);
    //qDebug() << outFile.toStdString();

    std::string inFileStr = inFile.toStdString();
    std::string outFileStr = outFile.toStdString();
    std::string keyStr = key.toStdString();
    std::string keyBits = algorithm.toStdString().substr(5, 3);
    std::string modeStr = mode.toStdString();
    std::string cipherName = algorithm.toStdString().substr(0, 4);

    encrypt(inFileStr, outFileStr, keyStr, keyBits, modeStr);
}


void MainWindow::on_pushButton_selectOutputFile_clicked()
{
    QString dirname = QFileDialog::getExistingDirectory(
        this,
        tr("Select a Directory"),
        QDir::homePath() + "/Desktop" );
    if( !dirname.isNull() )
    {
        qDebug() << dirname.toStdString();
    }
    ui->textEdit_pathOutputFile->setText(dirname);
}




void MainWindow::on_pushButton_selectInputFile_clicked()
{
    QString path = QFileDialog::getOpenFileName(0,QObject::tr("Укажите файл"),QDir::homePath() + "/Desktop", QObject::tr("Текстовый файл (*.txt);;Все файлы (*.*)"));
    ui->textEdit_pathInputFile->setText(path);
}

void MainWindow::on_pushButton_decrypt_clicked()
{
    QString inFile = ui->textEdit_pathInputFile->toPlainText();
    QString outFile = ui->textEdit_pathOutputFile->toPlainText();

    outFile += "/decrypted-" + inFile.section("/",-1,-1);
    //qDebug() << outFile.toStdString();

    QString key = ui->plainTextEdit_key->toPlainText();
    QString algorithm = ui->comboBox_algorithm->currentText();
    QString mode = ui->comboBox_mode->currentText();
    std::string inFileStr = inFile.toStdString();
    std::string outFileStr = outFile.toStdString();
    std::string keyStr = key.toStdString();
    std::string keyBits = algorithm.toStdString().substr(5, 3);
    std::string modeStr = mode.toStdString();
    std::string cipherName = algorithm.toStdString().substr(0, 4);

    decrypt(inFileStr, outFileStr, keyStr, keyBits, modeStr);
}

