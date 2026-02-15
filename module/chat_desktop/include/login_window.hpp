#ifndef LOGINWINDOW_H
#define LOGINWINDOW_H

#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QDialog>
#include <QApplication>
#include "home_page.hpp"


class LoginWindow : public QDialog {
    Q_OBJECT

public:
    LoginWindow(QWidget *parent = nullptr);
    ~LoginWindow();

public:
    void login(QApplication &app);

private slots:
    void onLoginClicked();
    void onRegisterClicked();
    void setupLoginUI();
    void connectSignals();

private:
    QScopedPointer<HomePage> chatWindow;

    QLabel *titleLb;
    QLabel *userNameLb;
    QLabel *passwdLb;

    QLineEdit *userNameEd;
    QLineEdit *passwdEd;

    QPushButton *loginBt;
    QPushButton *exitBt;
    QPushButton *registerBt;
};

#endif