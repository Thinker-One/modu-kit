#ifndef CUSTOMWIDGET_H
#define CUSTOMWIDGET_H

#include <QWidget>
#include <QLabel>
#include <QHBoxLayout>


class CustomWidget : public QWidget {

public:
    CustomWidget(const QString &text, QWidget *parent = nullptr);
    void setIconLabelContentsMargins(int left, int top, int right, int bottom);
    void setIconLabelFixedLengthWidth(int length, int width);
    void setIconLabelAlignment(Qt::Alignment alignment);
    void setIconSize(const QIcon &icon, int length, int width);
    void setTextLabelContentsMargins(int left, int top, int right, int bottom);
    void setTextLabelAlignment(Qt::Alignment alignment);
    void setTextLabelFixedLengthWidth(int length, int width);
    void setTextLabelContent(const QString &text);

private:
    QHBoxLayout *layout;
    QLabel *iconLabel;
    QLabel *textLabel;
};

#endif