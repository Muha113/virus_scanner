#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFileDialog>
#include <QDebug>
#include <QColor>
#include <iostream>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->scanningProgressBar->setValue(0);
    ui->scanningProgressBar->setMinimum(0);
    ui->scanningProgressBar->setMaximum(100);

    connect(&scan, SIGNAL(sendLogsEditText(QString)), this, SLOT(setLogsEditText(QString)));
    connect(&scan, SIGNAL(sendInfectedFilesEditText(QString)), this, SLOT(setInfectedFilesEditText(QString)));
    connect(&scan, SIGNAL(sendSignatureEditText(QString)), this, SLOT(setSignatureEditText(QString)));
    connect(&scan, SIGNAL(sendUpdateProgressBar()), this, SLOT(updateProgressBar()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setLogsEditText(QString str)
{
    ui->logsEdit->append(str);
}

void MainWindow::setInfectedFilesEditText(QString str)
{
    ui->infectedFilesEdit->append(str);
}

void MainWindow::setSignatureEditText(QString str)
{
    ui->signaturesEdit->append(str);
}

void MainWindow::updateProgressBar()
{
    ui->scanningProgressBar->setValue(ui->scanningProgressBar->value() + 1);
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

    ui->scanningProgressBar->setMinimum(0);
    ui->scanningProgressBar->setMaximum(scan.calculateFilesToScan(dirPath));
    ui->scanningProgressBar->setValue(0);

    pDir = opendir(dirPath);
    if (NULL == pDir)
    {
        ui->totalSummaryEdit->setTextColor(Qt::red);
        ui->logsEdit->setText("Invalid directory path provided!!\n");
        ui->totalSummaryEdit->setTextColor(Qt::black);
        pFile = fopen(dirPath, "rb");

        if(NULL == pFile)
        {
            ui->totalSummaryEdit->setTextColor(Qt::red);
            ui->logsEdit->setText("Invalid directory or file path\n");
            ui->totalSummaryEdit->setTextColor(Qt::black);
        }
        fclose(pFile);
        scan.buildSignaturesTable(sigPath);
        time(&sStartTime);
        scan.scanFileForViruses((char*)"", dirPath);
        time(&sEndTime);
    }
    else
    {
        closedir(pDir);

        if(scan.buildSignaturesTable(sigPath) == -1)
        {
            ui->totalSummaryEdit->setTextColor(Qt::red);
            ui->logsEdit->setText("Failed to open signatures files, exiting from scanning process\n");
            ui->totalSummaryEdit->setTextColor(Qt::black);
        }

        time(&sStartTime);
        scan.scanDirectories(dirPath);
        time(&sEndTime);
    }
    scan.setDTimeTakenToScanFiles(difftime(sEndTime, sStartTime));

    ui->totalSummaryEdit->setTextColor(Qt::darkGreen);
    ui->totalSummaryEdit->append("SUCCESS!\n");
    ui->totalSummaryEdit->setTextColor(Qt::black);
    ui->totalSummaryEdit->append("Virus Signatures: " + QString::number(scan.getUllTotalNumberOfVirusSignatures()));
    ui->totalSummaryEdit->append("Files Scanned: " + QString::number(scan.getUllTotalNumberOfFilesScanned()));
    if(scan.getUllTotalNumberOfInfectedFiles() != 0)
    {
        ui->totalSummaryEdit->setTextColor(Qt::red);
    }
    else
    {
        ui->totalSummaryEdit->setTextColor(Qt::Key_Green);
    }
    ui->totalSummaryEdit->append("Infected Files: " + QString::number(scan.getUllTotalNumberOfInfectedFiles()));
    ui->totalSummaryEdit->setTextColor(Qt::black);
    ui->totalSummaryEdit->append("Time: " +  QString::number(scan.getDTimeTakenToScanFiles()));
}
