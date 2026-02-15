#include <spdlog.hpp>
#include <QIcon>
#include "custom_widget.hpp"

CustomWidget::CustomWidget(const QString &text, QWidget *parent) : QWidget(parent) {
    layout = new QHBoxLayout(this);
    iconLabel = new QLabel;
    textLabel = new QLabel(text);
    // iconLabel->setStyleSheet("margin: 0px; padding: 0px; border: 1px solid black;");
    // textLabel->setStyleSheet("margin: 0px; padding: 0px; border: 1px solid black;");
    layout->setAlignment(textLabel, Qt::AlignTop);
    layout->setSpacing(10);
    layout->addWidget(iconLabel);
    layout->addWidget(textLabel);
    setLayout(layout);
}

void CustomWidget::setIconLabelContentsMargins(int left, int top, int right, int bottom) {
    iconLabel->setContentsMargins(left, top, right, bottom);
}
void CustomWidget::setIconLabelAlignment(Qt::Alignment alignment) {
    iconLabel->setAlignment(alignment);
}
void CustomWidget::setIconLabelFixedLengthWidth(int length, int width) {
    iconLabel->setFixedHeight(length);
    iconLabel->setFixedWidth(width);
}
void CustomWidget::setIconSize(const QIcon &icon, int length, int width) {
    iconLabel->setPixmap(icon.pixmap(35, 35));
    LOG_INFO("length={}, width={}", length, width);
}
void CustomWidget::setTextLabelContentsMargins(int left, int top, int right, int bottom) {
    textLabel->setContentsMargins(left, top, right, bottom);
}

void CustomWidget::setTextLabelAlignment(Qt::Alignment alignment) {
    textLabel->setAlignment(alignment);
}

void CustomWidget::setTextLabelFixedLengthWidth(int length, int width) {
    textLabel->setFixedWidth(length);
    textLabel->setFixedHeight(width);
}

void CustomWidget::setTextLabelContent(const QString &text) {
    textLabel->setText(text);
}