#include <QMessageBox>
#include <spdlog.hpp>
#include "login_window.hpp"

LoginWindow::LoginWindow(QWidget *parent) : QDialog(parent), chatWindow(new HomePage)
{
    setupLoginUI();
    connectSignals();
}

LoginWindow::~LoginWindow() {}

void LoginWindow::setupLoginUI() {

    setWindowTitle("LOGIN");
    resize(600, 400);

    // 创建控件
    titleLb = new QLabel("用户登录", this);
    titleLb->setAlignment(Qt::AlignCenter);
    titleLb->setStyleSheet("font-size: 20px; font-weight: bold;");
    userNameLb = new QLabel("用户名:", this);
    passwdLb = new QLabel("密码:", this);
    
    userNameEd = new QLineEdit(this);
    passwdEd = new QLineEdit(this);
    passwdEd->setEchoMode(QLineEdit::Password); // 密码显示为*

    loginBt = new QPushButton("登录", this);
    exitBt = new QPushButton("退出", this);

    // 布局管理
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(titleLb);

    QHBoxLayout *userLayout = new QHBoxLayout();
    userLayout->addWidget(userNameLb);
    userLayout->addWidget(userNameEd);

    QHBoxLayout *passLayout = new QHBoxLayout();
    passLayout->addWidget(passwdLb);
    passLayout->addWidget(passwdEd);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(loginBt);
    buttonLayout->addWidget(exitBt);

    mainLayout->addLayout(userLayout);
    mainLayout->addLayout(passLayout);
    mainLayout->addLayout(buttonLayout);
    
}

void LoginWindow::onLoginClicked() {

    QString username = userNameEd->text().trimmed();
    QString password = passwdEd->text();

    if (username.isEmpty() || password.isEmpty()) {
        QMessageBox::warning(this, "错误", "用户名和密码不能为空！");
        return;
    }

    if (username == "admin" && password == "123456") {
        QMessageBox::information(this, "成功", "登录成功！");
        this->accept();
    } else {
        QMessageBox::critical(this, "失败", "用户名或密码错误！");
    }
}

void LoginWindow::onRegisterClicked() {

}

void LoginWindow::connectSignals() {

    connect(loginBt, &QPushButton::clicked, this, &LoginWindow::onLoginClicked);
    connect(exitBt, &QPushButton::clicked, qApp, &QApplication::quit);
    // connect(userNameEd, &QLineEdit::returnPressed, this, &LoginWindow::onLoginClicked);
    // connect(passwdEd, &QLineEdit::returnPressed, this, &LoginWindow::onLoginClicked);

}

void LoginWindow::login(QApplication &app) {

    chatWindow->show();
    app.setApplicationVersion("1.0.0");
    // if (this->exec() == QDialog::Accepted) {
    //     chatWindow->show();
    // } else {
    //     QTimer::singleShot(0, &app, &QApplication::quit);
    // }

}