#include "hackprocesswindow.h"
#include "ui_hackprocesswindow.h"
HackProcessWindow::HackProcessWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::HackProcessWindow)
{
    ui->setupUi(this);

    processName = ui->processNameLineEdit;

    integrityLevel = ui->integrityLevelComboBox;

    libTable = ui->librariesTable;
}

HackProcessWindow::~HackProcessWindow()
{
    delete ui;
}

void HackProcessWindow::on_integrityLevelComboBox_currentIndexChanged(const QString &integrityLevelStr)
{
    if(integrityLevelStr == "Untrusted")
    {
        change_integraty(processNode,"Untrusted");
    }
    else if(integrityLevelStr == "Low")
    {
        change_integraty(processNode,"Low");
    }
    else if(integrityLevelStr == "Medium")
    {
        change_integraty(processNode,"Medium");
    }
    else if(integrityLevelStr == "High")
    {
        change_integraty(processNode,"High");
    }
}
