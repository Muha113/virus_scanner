#include "scanner.h"

Scanner::Scanner()
{
    ullTotalNumberOfFilesScanned = 0;
    ullTotalNumberOfInfectedFiles = 0;
    ullTotalNumberOfVirusSignatures = 0;
}

void Scanner::setDTimeTakenToScanFiles(double value)
{
    dTimeTakenToScanFiles = value;
}

unsigned long long Scanner::getUllTotalNumberOfVirusSignatures() const
{
    return ullTotalNumberOfVirusSignatures;
}

unsigned long long Scanner::getUllTotalNumberOfFilesScanned() const
{
    return ullTotalNumberOfFilesScanned;
}

unsigned long long Scanner::getUllTotalNumberOfInfectedFiles() const
{
    return ullTotalNumberOfInfectedFiles;
}

double Scanner::getDTimeTakenToScanFiles() const
{
    return dTimeTakenToScanFiles;
}

void Scanner::computeCommonInitialStr (const char *pcString, int iStringLen, int iDeltaTwo[])
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

void Scanner::constructDeltaOneTable (VirusSignatureTable_t * pVirusSigTable)
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

void Scanner::constructDeltaTwoTable(VirusSignatureTable_t * pVirusSigTable)
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

int Scanner::calculateFilesToScan(char *pcDirectoryPath)
{
    QString path = QString::fromLocal8Bit(pcDirectoryPath);
    QDirIterator it(path, QDirIterator::Subdirectories);
    QDir *currentDir = new QDir();
    currentDir->setPath(path);

    int filesCount = 0;

    while (it.hasNext())
    {
        it.next();
        if(it.fileName() != ".." && it.fileName() != "." && !it.fileInfo().isDir()) {
            filesCount++;
        }
    }
    return filesCount;
}

int Scanner::buildVirusSigTable (char *pcVirusSignature, VirusSignatureTable_t * pVirusSigTable)
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

int Scanner::buildSignaturesTable(char *pSignatureFile)
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

    pSigFile = fopen(pSignatureFile, "rb");

    if (NULL == pSigFile)
    {
        return -1;
    }

    fseek (pSigFile, 0, SEEK_END);
    lSignatureFileLen = ftell(pSigFile);
    rewind (pSigFile);

    pcVirusSignatures = ALLOC_BUFFER (lSignatureFileLen, char);
    fread(pcVirusSignatures, 1, lSignatureFileLen, pSigFile);

    pVirusSignatureTable[ullTotalNumberOfVirusSignatures] =
            ALLOC_BUFFER (sizeof (VirusSignatureTable_t), VirusSignatureTable_t);

    pcVirusSig = strtok (pcVirusSignatures, "\n");
    buildVirusSigTable(pcVirusSig, pVirusSignatureTable[ullTotalNumberOfVirusSignatures]);
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

int Scanner::scanBuffer (unsigned long long ullVirusTableIndex, char *pcBufferToBeScanned, long lBufferLength)
{
    unsigned long ulLengthDifference;
    unsigned long ulIterator;
    long     ulIndexJ;
    long     ulIndexM;
    long     ulIndexK;
    int      iASCIIValue;

    if(pVirusSignatureTable[ullVirusTableIndex]->iVirusLength > lBufferLength)
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
            iASCIIValue = 0;
            memcpy (&iASCIIValue, &pcBufferToBeScanned[ulIterator + ulIndexJ - 1], 1);
            ulIndexK = pVirusSignatureTable[ullVirusTableIndex]->iDeltaOne[iASCIIValue];

            if (ulIndexK < ulIndexJ && (ulIndexM = ulIndexJ - ulIndexK - 1) >
                pVirusSignatureTable[ullVirusTableIndex]->iDeltaTwo[ulIndexJ])
            {
                ulIterator = ulIterator + ulIndexM;
            }
            else
            {
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

int Scanner::scanFileForViruses (char *pcFileLocation)
{
    char     cAbsoluteFileLocation[1024];
    long     lFileLength;
    FILE    *pFile;
    char    *pcFileBuffer;
    unsigned long long ullIterator;
    int      iReturnStatus;
    int      iInfectedStatus;
    int      iSigIndex;

    strcpy (cAbsoluteFileLocation, pcFileLocation);

    QString absPath = QString::fromLocal8Bit(cAbsoluteFileLocation);

    emit sendLogsEditText("Open file: " + absPath, 0);

    pFile = fopen(cAbsoluteFileLocation, "rb");

    if (NULL == pFile)
    {
        emit sendLogsEditText("Cannot open file: " + absPath, -1);
        return -1;
    }

    emit sendLogsEditText("Scanning file: " + absPath, 0);

    fseek (pFile, 0, SEEK_END);
    lFileLength = ftell (pFile);
    rewind (pFile);

    pcFileBuffer = ALLOC_BUFFER (lFileLength, char);

    iReturnStatus = feof (pFile);
    iReturnStatus = fread (pcFileBuffer, 1, lFileLength, pFile);

    iInfectedStatus = 0;
    iSigIndex = 0;

    for (ullIterator = 0; ullIterator < ullTotalNumberOfVirusSignatures; ullIterator++)
    {
        iReturnStatus = scanBuffer(ullIterator, pcFileBuffer, lFileLength);
        if (VIRUS_FOUND == iReturnStatus)
        {
            iSigIndex = ullIterator;
            iInfectedStatus = 1;
        }
    }

    if(1 == iInfectedStatus)
    {
        QString sig = QString::fromLocal8Bit(pVirusSignatureTable[iSigIndex]->cVirus);

        emit sendSignatureEditText(sig);
        emit sendInfectedFilesEditText(absPath);

        ullTotalNumberOfInfectedFiles++;
    }

    free (pcFileBuffer);
    fclose (pFile);

    emit sendLogsEditText("Done!", 1);
    emit sendUpdateScannedFilesLabel();
    emit sendUpdateProgressBar();

    return VIRUS_NOT_FOUND;
}

void Scanner::scanDirectories (char *pcDirectoryPath)
{
    DIR     *pDir = NULL;
    int      iErrorInformation = -1;
    pDir = opendir(pcDirectoryPath);

    if (NULL == pDir)
    {
        emit sendLogsEditText("Failed to open directory!", -1);
        return;
    }

    QString path = QString::fromLocal8Bit(pcDirectoryPath);
    QDirIterator it(path, QDirIterator::Subdirectories);
    QDir *currentDir = new QDir();
    currentDir->setPath(path);

    while (it.hasNext())
    {
        it.next();
        if(it.fileName() != ".." && it.fileName() != "." && !it.fileInfo().isDir()) {
            QByteArray bt = it.filePath().toLocal8Bit();
            char* name = bt.data();
            iErrorInformation = scanFileForViruses(name);
            if(-1 != iErrorInformation)
            {
                ullTotalNumberOfFilesScanned++;
            }
        }
    }
    closedir(pDir);
}

//void printSinatureTable ()
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
