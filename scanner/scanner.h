#ifndef SCANNER_H
#define SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <QDir>
#include <QDirIterator>

#define ALLOC_BUFFER(size, dataType) (dataType*)memset(malloc(size), 0, size)
#define VIRUS_FOUND 0
#define VIRUS_NOT_FOUND 1
#define MAX_VIRUS_SIGNATURE_LEN  200
#define MAX_NUMBER_OF_VIRUS_SIGNATURES 1000000

unsigned long long ullTotalNumberOfVirusSignatures;
unsigned long long ullTotalNumberOfFilesScanned;
unsigned long long ullTotalNumberOfInfectedFiles;
double dTimeTakenToScanFiles;

typedef struct VirusSignatureTable
{
    char     cVirus[MAX_VIRUS_SIGNATURE_LEN];
    int      iVirusLength;
    int      iDeltaOne[256];
    int      iDeltaTwo[MAX_VIRUS_SIGNATURE_LEN];
} VirusSignatureTable_t;

VirusSignatureTable_t *pVirusSignatureTable[MAX_NUMBER_OF_VIRUS_SIGNATURES];

//static void printSinatureTable ()
//{
//    int i;
//    int j;

//    for (i = 0; (unsigned long long)i < ullTotalNumberOfVirusSignatures; i++)
//    {
//        printf("Virus Signature::%s\n", pVirusSignatureTable[i]->cVirus);
//        printf("DeltaOne Table\n");
//        printf
//                ("**********************************************************\n");
//        for (j = 0; j < 256; j++)
//        {
//            printf ("%d\n", pVirusSignatureTable[i]->iDeltaOne[j]);
//        }
//        printf ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
//        printf("DeltaTwo Table\n");
//        printf
//                ("**********************************************************\n");
//        for (j = 0; j < pVirusSignatureTable[i]->iVirusLength; j++)
//        {
//            printf ("%d\n", pVirusSignatureTable[i]->iDeltaTwo[j]);
//        }
//        printf ("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
//    }
//}

static void computeCommonInitialStr (const char *pcString, int iStringLen, int iDeltaTwo[])
{
    int      iIteratorOne;
    int      iIteratorTwo;

    iIteratorTwo = 0;

    for (iIteratorOne = 0; iIteratorOne < iStringLen; iIteratorOne++)
    {
        while (iIteratorTwo > 0 &&
               pcString[iIteratorTwo] != pcString[iIteratorOne])
        {
            iIteratorTwo = iDeltaTwo[iIteratorTwo - 1];
        }

        if (pcString[iIteratorOne] == pcString[iIteratorTwo])
        {
            iIteratorTwo++;
        }
        iDeltaTwo[iIteratorOne] = iIteratorTwo;
    }
}

static void constructDeltaOneTable (VirusSignatureTable_t * pVirusSigTable)
{
    int      iIterator;
    int      iASCIIChar;

    for (iIterator = 0; iIterator < 256; iIterator++)
    {
        pVirusSigTable->iDeltaOne[iIterator] = pVirusSigTable->iVirusLength;
    }

    for (iIterator = 0; iIterator < pVirusSigTable->iVirusLength; iIterator++)
    {
        iASCIIChar = (int) pVirusSigTable->cVirus[iIterator];
        pVirusSigTable->iDeltaOne[iASCIIChar] = iIterator;
    }

}

void constructDeltaTwoTable (VirusSignatureTable_t * pVirusSigTable)
{
    char     cReverseVirus[pVirusSigTable->iVirusLength + 1];
    char    *pcLeftChar;
    char    *pcRightChar;
    char    *pcTempStr;
    int      iIterator;
    int      iIndexOne;
    int      iIndextwo;
    int      iStrDeltaTwo[pVirusSigTable->iVirusLength];
    int      iRevStrDeltaTwo[pVirusSigTable->iVirusLength];

    pcLeftChar = pVirusSigTable->cVirus;
    pcRightChar = pVirusSigTable->cVirus + pVirusSigTable->iVirusLength;

    pcTempStr = cReverseVirus + pVirusSigTable->iVirusLength;

    *pcTempStr = 0;
    while (pcLeftChar < pcRightChar)
    {
        *(--pcTempStr) = *(pcLeftChar++);
    }

    computeCommonInitialStr (pVirusSigTable->cVirus, pVirusSigTable->iVirusLength, iStrDeltaTwo);
    computeCommonInitialStr (cReverseVirus, pVirusSigTable->iVirusLength, iRevStrDeltaTwo);

    for (iIterator = 0; iIterator <= pVirusSigTable->iVirusLength;
         iIterator++)
    {
        pVirusSigTable->iDeltaTwo[iIterator] =
                pVirusSigTable->iVirusLength -
                iStrDeltaTwo[pVirusSigTable->iVirusLength - 1];
    }

    for (iIterator = 0; iIterator < pVirusSigTable->iVirusLength; iIterator++)
    {
        iIndexOne = pVirusSigTable->iVirusLength - iRevStrDeltaTwo[iIterator];
        iIndextwo = iIterator - iRevStrDeltaTwo[iIterator] + 1;

        if (pVirusSigTable->iDeltaTwo[iIndexOne] > iIndextwo)
        {
            pVirusSigTable->iDeltaTwo[iIndexOne] = iIndextwo;
        }
    }
}

int buildVirusSigTable (char *pcVirusSignature, VirusSignatureTable_t * pVirusSigTable)
{
    int iVirusLength;

    if (NULL == pcVirusSignature || NULL == pVirusSigTable)
    {
        return -1;
    }

    iVirusLength = strlen (pcVirusSignature);
    strncpy (pVirusSigTable->cVirus, pcVirusSignature, iVirusLength);
    pVirusSigTable->cVirus[iVirusLength] = '\0';
    pVirusSigTable->iVirusLength = iVirusLength;
    constructDeltaOneTable (pVirusSigTable);
    constructDeltaTwoTable (pVirusSigTable);

    return 0;
}

int buildSignaturesTable(char *pSignatureFile)
{
    FILE    *pSigFile;
    char    *pcVirusSignatures;
    long     lSignatureFileLen;
    char    *pcVirusSig;

    pSigFile = NULL;
    lSignatureFileLen = 0;
    pcVirusSignatures = NULL;
    pcVirusSig = NULL;

    ullTotalNumberOfVirusSignatures = 0;

    pSigFile = fopen (pSignatureFile, "rb");

    if (NULL == pSigFile)
    {
        return -1;
    }

    fseek (pSigFile, 0, SEEK_END);
    lSignatureFileLen = ftell (pSigFile);
    rewind (pSigFile);

    pcVirusSignatures = ALLOC_BUFFER (lSignatureFileLen, char);
    fread (pcVirusSignatures, 1, lSignatureFileLen, pSigFile);

    pVirusSignatureTable[ullTotalNumberOfVirusSignatures] =
            ALLOC_BUFFER (sizeof (VirusSignatureTable_t), VirusSignatureTable_t);

    pcVirusSig = strtok (pcVirusSignatures, "\n");
    buildVirusSigTable (pcVirusSig, pVirusSignatureTable[ullTotalNumberOfVirusSignatures]);
    ullTotalNumberOfVirusSignatures++;

    while (1)
    {
        pcVirusSig = strtok (NULL, "\n");
        if (NULL == pcVirusSig)
        {
            break;
        }
        pVirusSignatureTable[ullTotalNumberOfVirusSignatures] =
                ALLOC_BUFFER(sizeof (VirusSignatureTable_t), VirusSignatureTable_t);
        buildVirusSigTable(pcVirusSig, pVirusSignatureTable[ullTotalNumberOfVirusSignatures]);
        ullTotalNumberOfVirusSignatures++;
    }

    // printSinatureTable();
    free (pcVirusSignatures);
    fclose (pSigFile);
    return 0;
}

static int scanBuffer (unsigned long long ullVirusTableIndex, char *pcBufferToBeScanned, long lBufferLength)
{
    unsigned long ulLengthDifference;
    unsigned long ulIterator;
    long     ulIndexJ;
    long     ulIndexM;
    long     ulIndexK;
    int      iASCIIValue;

    if (pVirusSignatureTable[ullVirusTableIndex]->iVirusLength >
        lBufferLength)
    {
        return VIRUS_NOT_FOUND;
    }

    ulLengthDifference = lBufferLength - pVirusSignatureTable[ullVirusTableIndex]->iVirusLength;

    ulIterator = 0;
    while (ulIterator < ulLengthDifference)
    {
        ulIndexJ = pVirusSignatureTable[ullVirusTableIndex]->iVirusLength;

        while (ulIndexJ > 0 && pVirusSignatureTable[ullVirusTableIndex]->cVirus[ulIndexJ - 1] ==
               pcBufferToBeScanned[ulIterator + ulIndexJ - 1])
        {
            ulIndexJ--;
        }

        if (ulIndexJ > 0)
        {
            //memset (&iASCIIValue, 0, 4);
            iASCIIValue = 0;
            memcpy (&iASCIIValue,
                    &pcBufferToBeScanned[ulIterator + ulIndexJ - 1], 1);
            ulIndexK =
                    pVirusSignatureTable[ullVirusTableIndex]->
                            iDeltaOne[iASCIIValue];

            if (ulIndexK < ulIndexJ &&
                (ulIndexM =
                         ulIndexJ - ulIndexK - 1) >
                pVirusSignatureTable[ullVirusTableIndex]->iDeltaTwo[ulIndexJ])
            {
                ulIterator = ulIterator + ulIndexM;
            }
            else
            {
                // pVirusSignatureTable[ullVirusTableIndex]->iDeltaTwo[ulIndexJ];
                ulIterator = ulIterator + ulIndexK;
            }
        }
        else
        {
            return VIRUS_FOUND;
        }
    }
    return VIRUS_NOT_FOUND;
}

static int scanFileForViruses (char *pcFileLocation, char *pcFileName)
{
    char     cAbsoluteFileLocation[1024];
    long     lFileLength;
    FILE    *pFile;
    char    *pcFileBuffer;
    unsigned long long ullIterator;
    int      iReturnStatus;
    int      iInfectedStatus;

    strcpy (cAbsoluteFileLocation, pcFileLocation);
    strcat (cAbsoluteFileLocation, "/");
    strcat (cAbsoluteFileLocation, pcFileName);

    pFile = fopen (cAbsoluteFileLocation, "rb");

    if (NULL == pFile)
    {
        return -1;
    }

    fseek (pFile, 0, SEEK_END);
    lFileLength = ftell (pFile);
    rewind (pFile);

    pcFileBuffer = ALLOC_BUFFER (lFileLength, char);

    iReturnStatus = feof (pFile);
    iReturnStatus = fread (pcFileBuffer, 1, lFileLength, pFile);

    iInfectedStatus = 0;
    for (ullIterator = 0; ullIterator < ullTotalNumberOfVirusSignatures;
         ullIterator++)
    {
        iReturnStatus = scanBuffer (ullIterator, pcFileBuffer, lFileLength);
        if (VIRUS_FOUND == iReturnStatus)
        {
//            printf ("%s Virus Signature Found in %s File\n",
//                    pVirusSignatureTable[ullIterator]->cVirus,
//                    cAbsoluteFileLocation);
            iInfectedStatus = 1;
            // return VIRUS_FOUND;
        }
    }

    if(1 == iInfectedStatus)
    {
        ullTotalNumberOfInfectedFiles++;
    }
    free (pcFileBuffer);
    fclose (pFile);

    return VIRUS_NOT_FOUND;
}

void scanDirectories (char *pcDirectoryPath)
{    
    DIR     *pDir = NULL;
    int      iErrorInformation = -1;
    pDir = opendir (pcDirectoryPath);

    if (NULL == pDir)
    {
        // printf ("Failed to open directory");
    }
    QString sosal = QString::fromLocal8Bit(pcDirectoryPath);
    QDirIterator it(sosal, QDirIterator::Subdirectories);
    QDir *currentDir = new QDir();
    currentDir->setPath(sosal);

    while (it.hasNext())
    {
        it.next();
        if(it.fileName() != ".." && it.fileName() != "." && !it.fileInfo().isDir()) {
            QByteArray bt = it.fileName().toLocal8Bit();
            char* name = bt.data();
            iErrorInformation = scanFileForViruses(pcDirectoryPath, name);
            if(-1 != iErrorInformation)
            {
                ullTotalNumberOfFilesScanned++;
            }
        }
    }
    closedir(pDir);
}

class Scanner
{
public:
    Scanner();
};

#endif // SCANNER_H

