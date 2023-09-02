#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpSocket>
#include <string>
#include <vector>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButton_6_clicked();

    void on_pushButton_4_clicked();

    void on_pushButton_encrypt_clicked();

    void on_pushButton_selectOutputFile_clicked();

    void on_pushButton_selectInputFile_clicked();

    void on_pushButton_decrypt_clicked();

private:
    Ui::MainWindow *ui;
    QTcpSocket *socket;
    QByteArray Data;
    void SendToServer(QString str);
    qint16 nextBlockSize;
    //std::vector<unsigned long long> keygen(const std::string &keyStr, int countDesKeys);
    void encrypt(const std::string& pathInFile, const std::string& pathOutFile, const std::string &keyStr, const std::string &keyBits, const std::string &mode);
    void decrypt(const std::string &pathInFile, const std::string &pathOutFile, const std::string &keyStr, const std::string &keyBits, const std::string &mode);

public slots:
    void slotReadyRead();
};
#endif // MAINWINDOW_H
