#include <string>
#include <QDebug>
#include <QTextCodec>

#include "Backend_files/stllist.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "hackprocesswindow.h"
#include "hackfilewindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    procInfoTable = ui->processesInfoTable;

    SetUpToolBar();
    UploadTable();
}

void MainWindow::SetUpToolBar()
{
    const QIcon refreshIcon = QIcon::fromTheme("Refresh", QIcon(":/Images/Refresh.png"));
    QAction *updateAct = new QAction(refreshIcon, tr("&Refresh"), this);
    updateAct->setStatusTip(tr("Refresh table information."));
    connect(updateAct, &QAction::triggered, this, &MainWindow::RefreshTable);
    ui->toolBar->addAction(updateAct);

    const QIcon hackProcessIcon = QIcon::fromTheme("Hack Process", QIcon(":/Images/HackProcess.png"));
    QAction *hackProcessAct = new QAction(hackProcessIcon, tr("&HackProcess"), this);
    hackProcessAct->setStatusTip(tr("Show additional information about process."));
    connect(hackProcessAct, &QAction::triggered, this, &MainWindow::HackProcess);
    ui->toolBar->addAction(hackProcessAct);

    const QIcon hackFileIcon = QIcon::fromTheme("Hack FIle", QIcon(":/Images/HackFile.png"));
    QAction *hackFileAct = new QAction(hackFileIcon, tr("&HackFile"), this);
    hackFileAct->setStatusTip(tr("Show additional information about file."));
    connect(hackFileAct, &QAction::triggered, this, &MainWindow::HackFile);
    ui->toolBar->addAction(hackFileAct);
}

void MainWindow::HackFile()
{
    QString pathToFile = QFileDialog::getOpenFileName(nullptr, QObject::tr("Выберите файл"), QDir::homePath(), QObject::tr("Все файлы (*.*)"));
    QString fileName =  pathToFile.right(pathToFile.size() -  pathToFile.lastIndexOf('/') - 1);

    HackFileWindow hfWindow;
    hfWindow.pathToFile->setText(pathToFile);
    hfWindow.fileName->setText(fileName);

    WCHAR path[MAX_PATH];
    pathToFile.toWCharArray(path);

    int integrLvl;
    if(FileSystemObjectInfo(path, integrLvl))
    {
        switch(integrLvl)
        {
        case 0:
            hfWindow.integrityLevel->setCurrentText("Low");
            break;

        case 1:
            hfWindow.integrityLevel->setCurrentText("Medium");
            break;

        case 2:
            hfWindow.integrityLevel->setCurrentText("High");
            break;

        case 3:
            hfWindow.integrityLevel->setCurrentText("High");
            break;

        case 4:
            hfWindow.integrityLevel->setCurrentText("Untrusted");
            break;
        }
    }
    else
    {
        qDebug() << "FileSystemObjectInfo failed";
    }

    list <info_file> fileAceList;
    acl_ace(fileAceList, pathToFile.toStdString().c_str());

    list <info_file> ::iterator iter = fileAceList.begin();
    if(iter->owner[0] != '\0')
    {
        hfWindow.owner->setText(QString::fromLocal8Bit(iter->owner));
        hfWindow.ownerSid->setText(iter->SID);
    }

    int rowCtr = 0;
    int iterIndex = 0;
    int aceIndx;
    for (iter = fileAceList.begin(); iter != fileAceList.end(); ++iter)
    {
        aceIndx = 0;
        while(iter->ACE[aceIndx][0] != '\0')
        {
            hfWindow.aclTable->insertRow(rowCtr);

            hfWindow.aclTable->setItem(rowCtr, 0, new QTableWidgetItem(QString::fromLocal8Bit(iter->owner)));
            hfWindow.aclTable->setItem(rowCtr, 1, new QTableWidgetItem(iter->ACE[aceIndx]));

            rowCtr++;
            aceIndx++;
        }

        iterIndex++;
    }
    hfWindow.isInitiated = 1;
    hfWindow.exec();
}

void MainWindow::HackProcess()
{
    int row = procInfoTable->currentRow();

    list <info> ::iterator iter;
    moveIterator(iter, row);

    HackProcessWindow hpWindow;
    hpWindow.processNode = iter;

    hpWindow.processName->setText(QString::fromStdWString(iter->name_PID));
    hpWindow.integrityLevel->setCurrentText(iter->integrityString);

    for(int i = 0; iter->DLL[i][0] != 0; i++)
    {
        hpWindow.libTable->insertRow(i);
        hpWindow.libTable->setItem(i, 0, new QTableWidgetItem(iter->DLL[i]));
    }

    hpWindow.exec();
}

void MainWindow::RefreshTable()
{
    this->ClearTable();
    this->UploadTable();
}

void MainWindow::UploadTable()
{
    setlocale(LC_ALL,"Russian");
    QTextCodec::setCodecForLocale(QTextCodec::codecForName("Windows-1251"));

    ::procInfoList.clear();

    FillProcInfoList(::procInfoList);

    list <info> ::iterator iter;
    int rowCtr = 0;
    for (iter = ::procInfoList.begin(); iter != ::procInfoList.end(); ++iter)
    {
        procInfoTable->insertRow(rowCtr);

        procInfoTable->setItem(rowCtr, 0, new QTableWidgetItem(QString::fromStdWString(iter->name_PID)));
        procInfoTable->setItem(rowCtr, 1, new QTableWidgetItem(QString::number(iter->num_PID)));
        procInfoTable->setItem(rowCtr, 2, new QTableWidgetItem(iter->path));
        procInfoTable->setItem(rowCtr, 3, new QTableWidgetItem(iter->par_name));
        procInfoTable->setItem(rowCtr, 4, new QTableWidgetItem(QString::number(iter->num_par_PID)));
        procInfoTable->setItem(rowCtr, 5, new QTableWidgetItem(QString::fromLocal8Bit(iter->ownerName)));
        procInfoTable->setItem(rowCtr, 6, new QTableWidgetItem(iter->SID));
        procInfoTable->setItem(rowCtr, 7, new QTableWidgetItem(QString::number(iter->x_bit)));
        procInfoTable->setItem(rowCtr, 8, new QTableWidgetItem(iter->DEP));
        procInfoTable->setItem(rowCtr, 9, new QTableWidgetItem(iter->ASLR));

        rowCtr++;
    }
}

void MainWindow::ClearTable()
{
    procInfoTable->setRowCount(0);
}

void MainWindow::FillProcInfoList(std::list<info>& procInfoList)
{
    get_first_three(procInfoList);
    know_your_parent(procInfoList);
    the_name_of_parent(procInfoList);
    the_username_sid(procInfoList);
    x_32_64(procInfoList);
    get_dep_aslr(procInfoList);
    about_dll(procInfoList);
    mandatory_integrity(procInfoList);
}

MainWindow::~MainWindow()
{
    delete ui;
}

