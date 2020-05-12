#include "mainwindow.h"
#include "ui_mainwindow.h"

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

}
