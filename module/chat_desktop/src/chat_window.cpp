#include <spdlog.hpp>
#include "chat_window.hpp"

ChatWindow::ChatWindow(const QString &text, QWidget *parent) : QWidget(parent) {
    initChatWindow(text);
    connectSignals();
}

void ChatWindow::initChatWindow(const QString &text) {

    chatLayout = new QVBoxLayout(this);
    chatContent = new QTextEdit(this);
    chatContent->setReadOnly(true);
    chatContent->append(text);
    chatLayout->addWidget(chatContent);

    inputLayout = new QHBoxLayout();
    inputBox = new QLineEdit(this);
    sendButton = new QPushButton("发送", this);
    inputLayout->addWidget(inputBox);
    inputLayout->addWidget(sendButton);
    chatLayout->addLayout(inputLayout);
}

void ChatWindow::connectSignals() {

    connect(sendButton, &QPushButton::clicked, this, &ChatWindow::sendMessage);
    connect(inputBox, &QLineEdit::returnPressed, this, &ChatWindow::sendMessage);
}

void ChatWindow::sendMessage() {
    LOG_DEBUG("发送消息");
}