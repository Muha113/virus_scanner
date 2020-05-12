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
}

void MainWindow::on_startScanButton_clicked()
{
    DIR     *pDir;
    FILE    *pFile;
    time_t  sStartTime;
    time_t  sEndTime;
    pDir = NULL;
    char* dirPath = "C:\\Users\\danii\\CLionProjects\\virus_scanner\\pkg";
    char* sigPath = "C:\\Users\\danii\\CLionProjects\\virus_scanner\\pkg\\signatures";
    int iArgCount = 3;
//    if (iArgCount < 3)
//    {
//        printf ("Usage:%s <Directory Path> <Signatures File>\n", ppcArgs[0]);
//        ui->
//    }

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
        scanFileForViruses("", dirPath);
        time(&sEndTime);
        goto scan_summary;
    }

    closedir(pDir);

    if(buildSignaturesTable(sigPath) == -1)
    {
        ui->logsEdit->setText("Failed to open signatures files, exiting from scanning process\n");
    }

    time(&sStartTime);
    scanDirectories (dirPath);
    time(&sEndTime);

    scan_summary:
    dTimeTakenToScanFiles = difftime(sEndTime, sStartTime);
//    printf("\n\n-------------------------------\n");
//    printf("SCAN SUMMARY\n");
//    printf("-------------------------------\n");
//    printf("Number Of Virus Signatures: %lld\n", ullTotalNumberOfVirusSignatures);
//    printf("Number Of Files Scanned   : %lld\n", ullTotalNumberOfFilesScanned);
//    printf("Number Of Infected Files  : %lld\n", ullTotalNumberOfInfectedFiles);
//    printf("Time Taken To Scan Files  : %0.2fSecs\n", dTimeTakenToScanFiles);
//    printf("-------------------------------\n");
//    return (EXIT_SUCCESS);
    ui->logsEdit->setText("SUCCESS\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Number Of Virus Signatures: " + QString::number(ullTotalNumberOfVirusSignatures) + "\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Number Of Files Scanned: " + QString::number(ullTotalNumberOfFilesScanned) + "\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Number Of Infected Files: " + QString::number(ullTotalNumberOfInfectedFiles) + "\n");
    ui->logsEdit->setText(ui->logsEdit->toPlainText() + "Time Taken To Scan Files: " +  QString::number(dTimeTakenToScanFiles) + "\n");
}
