#ifndef CHATWINDOW_H
#define CHATWINDOW_H

#include <QTextEdit>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>


class ChatWindow : public QWidget
{
public:
    ChatWindow(const QString &text, QWidget *parent = nullptr);

public:
    void initChatWindow(const QString &text);

private:
    void connectSignals();

private slots:
    void sendMessage();
    

private:
    QVBoxLayout *chatLayout;
    QHBoxLayout *inputLayout;
    QTextEdit *chatContent;
    QLineEdit *inputBox;
    QPushButton *sendButton;

};

#endif