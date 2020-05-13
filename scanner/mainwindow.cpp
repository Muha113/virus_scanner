#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "scanner.h"

#include <QFileDialog>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_chooseDirButton_clicked()
{
    QString path = QFileDialog::getExistingDirectory(0, "Directory dialogue", "");
    ui->pathDirEdit->setText(path);
    directoryPath = path;
}

void MainWindow::on_chooseSigFileButton_clicked()
{
    QString path = QFileDialog::getOpenFileName(0, "Open dialogue", "", "*.txt");
    ui->pathSigFileEdit->setText(path);
    signaturesPath = path;
}

void MainWindow::on_startScanButton_clicked()
{
    DIR     *pDir;
    FILE    *pFile;
    time_t  sStartTime;
    time_t  sEndTime;
    pDir = NULL;
    char* dirPath;
    char* sigPath;

    QByteArray dirPathByte = directoryPath.toLocal8Bit();
    dirPath = dirPathByte.data();
    QByteArray sigPathByte = signaturesPath.toLocal8Bit();
    sigPath = sigPathByte.data();

    pDir = opendir(dirPath);
    if (NULL == pDir)
    {
        ui->logsEdit->setText("Invalid directory path provided!!\n");
        pFile = fopen(dirPath, "rb");

        if(NULL == pFile)
        {
            ui->logsEdit->setText("Invalid directory or file path\n");
        }
        fclose(pFile);
        buildSignaturesTable (sigPath);
        time(&sStartTime);
        scanFileForViruses((char*)"", dirPath);
        time(&sEndTime);
    }
    else
    {
        closedir(pDir);

        if(buildSignaturesTable(sigPath) == -1)
        {
            ui->logsEdit->setText("Failed to open signatures files, exiting from scanning process\n");
        }

        time(&sStartTime);
        scanDirectories (dirPath);
        time(&sEndTime);
    }

    dTimeTakenToScanFiles = difftime(sEndTime, sStartTime);

    ui->logsEdit->setText("SUCCESS\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Number Of Virus Signatures: " + QString::number(ullTotalNumberOfVirusSignatures) + "\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Number Of Files Scanned: " + QString::number(ullTotalNumberOfFilesScanned) + "\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Number Of Infected Files: " + QString::number(ullTotalNumberOfInfectedFiles) + "\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Time Taken To Scan Files: " +  QString::number(dTimeTakenToScanFiles) + "\n");
}
