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
    QIcon icon = QIcon("C:\\Users\\danii\\Documents\\virus_scanner\\scanner\\scannerIcon.jpg");
    this->setWindowIcon(icon);

    ui->signaturesEdit->setReadOnly(true);
    ui->infectedFilesEdit->setReadOnly(true);
    ui->logsEdit->setReadOnly(true);

    ui->scanningProgressBar->setValue(0);
    ui->scanningProgressBar->setMinimum(0);
    ui->scanningProgressBar->setMaximum(100);
    ui->filesScannedLabel->setText(QString::number(0));

    connect(&scan, SIGNAL(sendLogsEditText(QString, int)), this, SLOT(setLogsEditText(QString, int)));
    connect(&scan, SIGNAL(sendInfectedFilesEditText(QString)), this, SLOT(setInfectedFilesEditText(QString)));
    connect(&scan, SIGNAL(sendSignatureEditText(QString)), this, SLOT(setSignatureEditText(QString)));
    connect(&scan, SIGNAL(sendUpdateProgressBar()), this, SLOT(updateProgressBar()));
    connect(&scan, SIGNAL(sendUpdateScannedFilesLabel()), this, SLOT(updateScannedFilesLabel()));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setLogsEditText(QString str, int type)
{
    switch(type)
    {
    case -1:
        ui->logsEdit->setTextColor(Qt::red);
        ui->logsEdit->append(str);
        ui->logsEdit->setTextColor(Qt::black);
        break;
    case 0:
        ui->logsEdit->append(str);
        break;
    case 1:
        ui->logsEdit->setTextColor(Qt::green);
        ui->logsEdit->append(str);
        ui->logsEdit->setTextColor(Qt::black);
        break;
    }
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

void MainWindow::updateScannedFilesLabel()
{
    int scanned = ui->filesScannedLabel->text().toInt();
    ui->filesScannedLabel->setText(QString::number(scanned + 1));
}

void MainWindow::on_chooseDirButton_clicked()
{
    QString path = QFileDialog::getExistingDirectory(0, "Directory dialogue", "");
    if(path != "")
    {
        ui->pathDirEdit->setText(path);
        ui->logsEdit->clear();
        QByteArray bt = path.toLocal8Bit();
        char *pathToScan = bt.data();
        filesToScan = scan.calculateFilesToScan(pathToScan);
        ui->fileReadyToScanLabel->setText(QString::number(filesToScan));
        directoryPath = path;
    }
    else
    {
        ui->logsEdit->setTextColor(Qt::red);
        ui->logsEdit->setText("Invalid directory path\n");
        ui->logsEdit->setTextColor(Qt::black);
    }
}

void MainWindow::on_chooseSigFileButton_clicked()
{
    QString path = QFileDialog::getOpenFileName(0, "Open dialogue", "", "*.txt");
    if(path != "")
    {
        ui->pathSigFileEdit->setText(path);
        ui->logsEdit->clear();
        signaturesPath = path;
    }
    else
    {
        ui->logsEdit->setTextColor(Qt::red);
        ui->logsEdit->setText("Invalid signature file path\n");
        ui->logsEdit->setTextColor(Qt::black);
    }
}

void MainWindow::on_startScanButton_clicked()
{
    ui->statusLabel->setText("RUNNING");

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
    ui->scanningProgressBar->setMaximum(filesToScan);
    ui->scanningProgressBar->setValue(0);

    pDir = opendir(dirPath);
    if (NULL == pDir)
    {
        ui->logsEdit->setTextColor(Qt::red);
        ui->logsEdit->setText("Invalid directory path provided!!\n");
        ui->logsEdit->setTextColor(Qt::black);
        pFile = fopen(dirPath, "rb");

        if(NULL == pFile)
        {
            ui->logsEdit->setTextColor(Qt::red);
            ui->logsEdit->setText("Invalid directory or file path\n");
            ui->logsEdit->setTextColor(Qt::black);
            ui->statusLabel->setStyleSheet("QLabel { color : red; }");
            ui->statusLabel->setText("FAILED");
        }

        fclose(pFile);
        scan.buildSignaturesTable(sigPath);
        time(&sStartTime);
        scan.scanFileForViruses(dirPath);
        time(&sEndTime);
    }
    else
    {
        closedir(pDir);

        if(scan.buildSignaturesTable(sigPath) == -1)
        {
            ui->logsEdit->setTextColor(Qt::red);
            ui->logsEdit->setText("Failed to open signatures files, exiting from scanning process\n");
            ui->logsEdit->setTextColor(Qt::black);
        }

        time(&sStartTime);
        scan.scanDirectories(dirPath);
        time(&sEndTime);
    }

    scan.setDTimeTakenToScanFiles(difftime(sEndTime, sStartTime));

    ui->statusLabel->setStyleSheet("QLabel { color : green; }");
    ui->statusLabel->setText("SUCCESS");
    ui->availableSigsLabel->setText(QString::number(scan.getUllTotalNumberOfVirusSignatures()));
    ui->totalFilesScannedLabel->setText(QString::number(scan.getUllTotalNumberOfFilesScanned()));
    if(scan.getUllTotalNumberOfInfectedFiles() != 0)
    {
        ui->totalInfectedFilesLabel->setStyleSheet("QLabel { color : red; }");
        ui->label_12->setStyleSheet("QLabel { color : red; }");
    }
    else
    {
        ui->totalInfectedFilesLabel->setStyleSheet("QLabel { color : green; }");
        ui->label_12->setStyleSheet("QLabel { color : green; }");
    }
    ui->totalInfectedFilesLabel->setText(QString::number(scan.getUllTotalNumberOfInfectedFiles()));
    ui->timeScanningLabel->setText(QString::number(scan.getDTimeTakenToScanFiles()) + " sec.");
}
