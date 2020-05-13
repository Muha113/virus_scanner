#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <QDir>
#include <QDirIterator>
#include <QDebug>
#include <QObject>
#include <iostream>

#define ALLOC_BUFFER(size, dataType) (dataType*)memset(malloc(size), 0, size)
#define VIRUS_FOUND 0
#define VIRUS_NOT_FOUND 1
#define MAX_VIRUS_SIGNATURE_LEN  200
#define MAX_NUMBER_OF_VIRUS_SIGNATURES 10000

typedef struct VirusSignatureTable
{
    char     cVirus[MAX_VIRUS_SIGNATURE_LEN];
    int      iVirusLength;
    int      iDeltaOne[256];
    int      iDeltaTwo[MAX_VIRUS_SIGNATURE_LEN];
} VirusSignatureTable_t;


class Scanner : public QObject
{
Q_OBJECT
public:
    Scanner();
    void computeCommonInitialStr (const char*, int, int[]);
    void constructDeltaOneTable (VirusSignatureTable_t*);
    void constructDeltaTwoTable (VirusSignatureTable_t*);
    int calculateFilesToScan(char*);
    int buildVirusSigTable (char*, VirusSignatureTable_t*);
    int buildSignaturesTable(char*);
    int scanBuffer (unsigned long long, char*, long);
    int scanFileForViruses (char*, char*);
    void scanDirectories (char*);
    unsigned long long getUllTotalNumberOfVirusSignatures() const;
    unsigned long long getUllTotalNumberOfFilesScanned() const;
    unsigned long long getUllTotalNumberOfInfectedFiles() const;
    double getDTimeTakenToScanFiles() const;
    void setDTimeTakenToScanFiles(double value);

signals:
    void sendLogsEditText(QString);
    void sendInfectedFilesEditText(QString);
    void sendSignatureEditText(QString);
    void sendUpdateProgressBar();

private:
    VirusSignatureTable_t *pVirusSignatureTable[MAX_NUMBER_OF_VIRUS_SIGNATURES];
    unsigned long long ullTotalNumberOfVirusSignatures;
    unsigned long long ullTotalNumberOfFilesScanned;
    unsigned long long ullTotalNumberOfInfectedFiles;
    double dTimeTakenToScanFiles;
};

#endif // SCANNER_H

