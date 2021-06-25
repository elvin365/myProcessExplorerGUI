#include "Backend_files/stllist.h"
#include "hackfilewindow.h"
#include "ui_hackfilewindow.h"


HackFileWindow::HackFileWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::HackFileWindow)
{
    ui->setupUi(this);

    integrityLevel = ui->integrityLevelComboBox;
    owner = ui->ownerLineEdit;

    fileName = ui->fileNameLineEdit;
    pathToFile = ui->pathToFileLineEdit;
    ownerSid = ui->ownerSidLineEdit;

    aclTable = ui->aclTable;

    isInitiated = 0;
}

HackFileWindow::~HackFileWindow()
{
    delete ui;
}

void HackFileWindow::on_integrityLevelComboBox_currentIndexChanged(const QString &arg1)
{

    if(!isInitiated)
    {
        return;
    }

    bool res;

    QString integrityLevelStr = arg1;

    WCHAR wszLowIntegritySid[20] = L"S-1-16-4096";
    WCHAR wszMediumIntegritySid[20] = L"S-1-16-8192";
    WCHAR wszHighIntegritySid[20] = L"S-1-16-12288";
    WCHAR wszUntrustedIntegritySid[20] = L"S-1-16-0";

    WCHAR path[MAX_PATH];
    (this->pathToFile->text()).toWCharArray(path);

    qDebug() << "path = " << this->pathToFile->text();

    if(integrityLevelStr == "Untrusted")
    {
        res = setLevel(path, 0);
    }
    else if(integrityLevelStr == "Low")
    {
        res = setLevel(path, 1);
    }
    else if(integrityLevelStr == "Medium")
    {
      res =  setLevel(path, 2);
    }
    else if(integrityLevelStr == "High")
    {
       res =  setLevel(path, 3);
    }

    qDebug() << "Set level result = " << res ;
}
