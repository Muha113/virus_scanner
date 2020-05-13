#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "scanner.h"

#include <QMainWindow>
#include <QObject>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void setLogsEditText(QString, int);
    void setInfectedFilesEditText(QString);
    void setSignatureEditText(QString);
    void updateProgressBar();
    void updateScannedFilesLabel();

private slots:
    void on_chooseDirButton_clicked();
    void on_startScanButton_clicked();
    void on_chooseSigFileButton_clicked();

private:
    Ui::MainWindow *ui;
    QString directoryPath;
    QString signaturesPath;
    Scanner scan;
    int filesToScan;
};
#endif // MAINWINDOW_H
